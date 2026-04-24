#!/usr/bin/env python3

"""
Detect whether a DNS zone uses UltraDNS-style minimally covering NSEC
records (white lies) by probing the zone with DNS queries and analyzing
the NSEC records in negative responses.

By default, uses the local system resolver. Use --doh to query via
DNS-over-HTTPS to Cloudflare (or a custom server with --doh-server).
"""

import sys
import string
import random
import argparse

import dns.name
import dns.query
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.flags

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

QUERY_MODE = "local"
DOH_URL = DEFAULT_DOH_URL

ULTRADNS_ALPHABET = "!-0123456789_abcdefghijklmnopqrstuvwxyz~"

PREV_CHAR = {}
for i, ch in enumerate(ULTRADNS_ALPHABET):
    if i > 0:
        PREV_CHAR[ch] = ULTRADNS_ALPHABET[i - 1]


def query_dns(qname, rdtype, want_dnssec=True):
    """Send a DNS query and return the response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
    q.flags |= dns.flags.AD
    if QUERY_MODE == "doh":
        return dns.query.https(q, DOH_URL)
    else:
        resolver = dns.resolver.Resolver()
        nameserver = resolver.nameservers[0]
        return dns.query.udp(q, nameserver)


def get_nsec_records(response):
    """Extract NSEC RRsets from the authority section."""
    nsec_rrsets = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            nsec_rrsets.append(rrset)
    return nsec_rrsets


def check_dnssec_enabled(zone_name):
    """Verify the zone has DNSSEC by looking for RRSIG in a SOA response."""
    response = query_dns(zone_name, "SOA")
    if response.rcode() != dns.rcode.NOERROR:
        return False, "Zone does not exist or SOA query failed"
    has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG
        for rrset in response.answer
    )
    if not has_rrsig:
        return False, "No RRSIG in SOA response — DNSSEC not enabled or resolver not validating"
    return True, "DNSSEC enabled"


def random_label(length=8):
    """Generate a random lowercase label unlikely to exist."""
    chars = string.ascii_lowercase
    return ''.join(random.choice(chars) for _ in range(length))


def check_apex_wildcard(zone_name):
    """Check if the zone has an apex wildcard by querying a random name."""
    test_name = dns.name.from_text(f"{random_label(12)}.{zone_name}")
    response = query_dns(test_name, "A")
    rcode = response.rcode()
    if rcode == dns.rcode.NOERROR and len(response.answer) > 0:
        return True
    return False


def find_nxdomain_parent(zone_name):
    """
    Find a parent name under which we can elicit NXDOMAIN responses.
    Returns (parent_name, method) or (None, reason).
    """
    test_label = random_label(12)
    test_name = dns.name.from_text(f"{test_label}.{zone_name}")
    response = query_dns(test_name, "A")
    rcode = response.rcode()

    if rcode == dns.rcode.NXDOMAIN:
        return zone_name, "direct"

    if rcode == dns.rcode.NOERROR and len(response.answer) > 0:
        return None, "apex_wildcard"

    return None, f"unexpected_rcode_{dns.rcode.to_text(rcode)}"


def expected_predecessor_label(qname_label):
    """
    Compute the expected UltraDNS predecessor base label for a given label.
    Returns the modified label (without the leading ~ child labels).
    The actual predecessor will be one or more ~ child labels prepended
    to this base label.
    """
    label = qname_label.lower()
    last_char = label[-1]

    if last_char in PREV_CHAR:
        prev = PREV_CHAR[last_char]
    else:
        for i in range(len(ULTRADNS_ALPHABET) - 1, -1, -1):
            if ULTRADNS_ALPHABET[i] < last_char:
                prev = ULTRADNS_ALPHABET[i]
                break
        else:
            return label[:-1]

    return label[:-1] + prev + "~"


def expected_successor_label(qname_label):
    """Compute the expected UltraDNS successor: label + '!'"""
    return qname_label.lower() + "!"


def match_nsec_pattern(test_label, parent_name, nsec_records, verbose, details):
    """
    Check if NSEC records match UltraDNS patterns for a given query label.
    Returns a score: 1.0 for full match, 0.5 for successor-only, 0 for no match.
    """
    name_covering = None

    for rrset in nsec_records:
        for rdata in rrset:
            next_name = rdata.next
            next_labels = next_name.relativize(parent_name)
            next_first_label = next_labels[0].decode().lower()
            if next_first_label == expected_successor_label(test_label):
                name_covering = (rrset.name, next_name)

    if not name_covering:
        if verbose:
            details.append(f"  {test_label}: could not identify name-covering NSEC")
        return 0

    owner, nxt = name_covering
    owner_rel = owner.relativize(parent_name)
    exp_base = expected_predecessor_label(test_label)
    owner_labels = [l.decode().lower() for l in owner_rel.labels]

    pred_match = False
    if len(owner_labels) >= 1:
        base_label = owner_labels[-1]
        tilde_labels = owner_labels[:-1]
        if base_label == exp_base and all(l == "~" for l in tilde_labels):
            pred_match = True

    succ_str = nxt.relativize(parent_name)[0].decode().lower()
    succ_match = succ_str == expected_successor_label(test_label)

    if verbose:
        depth = len(owner_labels) - 1 if pred_match else "?"
        details.append(f"  {test_label}: NSEC owner={owner} next={nxt}")
        details.append(f"    successor match: {succ_match}, predecessor match: {pred_match} (depth={depth})")
        if not pred_match:
            details.append(f"    expected base: {exp_base}, got labels: {owner_labels}")

    if succ_match and pred_match:
        return 1.0
    elif succ_match:
        return 0.5
    return 0


def check_nsec_patterns(zone_name, parent_name, has_wildcard=False, verbose=False):
    """
    Query for random non-existent names and check if NSEC records
    match UltraDNS patterns. Works with both NXDOMAIN responses and
    wildcard-synthesized responses. Returns (matches, total, details).
    """
    num_tests = 5
    matches = 0
    details = []

    for i in range(num_tests):
        test_label = random_label(6 + i)
        test_fqdn = dns.name.from_text(f"{test_label}.{parent_name}")
        response = query_dns(test_fqdn, "A")
        rcode = response.rcode()

        if rcode == dns.rcode.NXDOMAIN:
            nsec_records = get_nsec_records(response)
            if not nsec_records:
                details.append(f"  {test_fqdn}: no NSEC records (might be NSEC3)")
                continue
            score = match_nsec_pattern(test_label, parent_name, nsec_records, verbose, details)
            matches += score
        elif rcode == dns.rcode.NOERROR and has_wildcard:
            nsec_records = get_nsec_records(response)
            if not nsec_records:
                details.append(f"  {test_fqdn}: wildcard match but no NSEC records")
                continue
            score = match_nsec_pattern(test_label, parent_name, nsec_records, verbose, details)
            matches += score
        else:
            details.append(f"  {test_fqdn}: unexpected rcode {dns.rcode.to_text(rcode)}")

    return matches, num_tests, details


def check_nodata_nsec(zone_name, verbose=False):
    """
    Query the zone apex for a type it doesn't have and check the NSEC
    successor pattern.
    """
    response = query_dns(zone_name, "LOC")
    rcode = response.rcode()
    if rcode != dns.rcode.NOERROR:
        return None, f"apex NODATA query returned {dns.rcode.to_text(rcode)}"

    nsec_records = get_nsec_records(response)
    if not nsec_records:
        return None, "no NSEC in NODATA response (might be NSEC3)"

    for rrset in nsec_records:
        if rrset.name == zone_name:
            for rdata in rrset:
                next_name = rdata.next
                if next_name.is_subdomain(zone_name) and next_name != zone_name:
                    first_label = next_name.relativize(zone_name)[0].decode()
                    if first_label == "!":
                        return True, f"apex NODATA: next={next_name} (child label '!')"
                    else:
                        return False, f"apex NODATA: next={next_name} (unexpected child label '{first_label}')"
    return None, "could not find matching NSEC for apex"


def check_for_nsec3(zone_name):
    """Check if the zone uses NSEC3 instead of NSEC."""
    test_name = dns.name.from_text(f"{random_label(10)}.{zone_name}")
    response = query_dns(test_name, "A")
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC3:
            return True
    return False


def detect(zone_str, verbose=False):
    """Main detection routine."""
    zone_name = dns.name.from_text(zone_str)
    print(f"\nAnalyzing zone: {zone_name}")
    print(f"{'=' * 60}")

    print("\n[1] Checking DNSSEC...")
    enabled, msg = check_dnssec_enabled(zone_name)
    print(f"  {msg}")
    if not enabled:
        print("\nResult: Cannot determine — DNSSEC not available")
        return False

    print("\n[2] Checking for NSEC3...")
    if check_for_nsec3(zone_name):
        print("  Zone uses NSEC3, not NSEC")
        print("\nResult: NOT UltraDNS-style NSEC white lies (uses NSEC3)")
        return False
    print("  Zone uses NSEC (not NSEC3)")

    print("\n[3] Checking apex NODATA response...")
    apex_match, apex_msg = check_nodata_nsec(zone_name, verbose)
    print(f"  {apex_msg}")

    print("\n[4] Finding query strategy...")
    parent, method = find_nxdomain_parent(zone_name)
    has_wildcard = False
    if method == "apex_wildcard":
        has_wildcard = True
        parent = zone_name
        print(f"  Zone has apex wildcard — will test NSEC patterns from wildcard responses")
    elif parent is None:
        print(f"  Could not determine query strategy ({method})")
        if apex_match:
            print("\nResult: LIKELY UltraDNS-style (apex NODATA matches, but could not test NSEC)")
        else:
            print("\nResult: INCONCLUSIVE")
        return apex_match or False
    else:
        print(f"  Using parent: {parent} ({method})")

    print(f"\n[5] Testing NSEC patterns ({parent})...")
    matches, total, details = check_nsec_patterns(
        zone_name, parent, has_wildcard=has_wildcard, verbose=verbose)
    for d in details:
        print(d)
    print(f"  Score: {matches}/{total} queries matched UltraDNS pattern")

    print(f"\n{'=' * 60}")
    apex_str = "YES" if apex_match else ("N/A" if apex_match is None else "NO")
    print(f"  Apex NODATA match:  {apex_str}")
    print(f"  NXDOMAIN match:     {matches}/{total}")

    if matches >= total * 0.8 and apex_match:
        print("\nResult: DETECTED — Zone uses UltraDNS-style minimally covering NSEC")
        return True
    elif matches >= total * 0.5:
        print("\nResult: LIKELY — Zone appears to use UltraDNS-style NSEC white lies")
        return True
    else:
        print("\nResult: NOT DETECTED — Zone does not appear to use UltraDNS-style NSEC")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Detect UltraDNS-style minimally covering NSEC records")
    parser.add_argument("zone", help="DNS zone name to analyze")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed NSEC analysis")
    parser.add_argument("--doh", action="store_true",
                        help="Use DNS-over-HTTPS (default server: Cloudflare)")
    parser.add_argument("--doh-server", metavar="URL",
                        help="DoH server URL (implies --doh)")
    args = parser.parse_args()

    global QUERY_MODE, DOH_URL
    if args.doh or args.doh_server:
        QUERY_MODE = "doh"
        if args.doh_server:
            DOH_URL = args.doh_server

    zone = args.zone
    if not zone.endswith('.'):
        zone += '.'

    try:
        detect(zone, verbose=args.verbose)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
