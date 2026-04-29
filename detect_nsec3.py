#!/usr/bin/env python3

"""
Detect whether a DNS zone uses traditional (pre-computed) NSEC3 or
NSEC3 White Lies (online-signed, RFC 7129 Appendix B).

Probes the zone with random nonexistent names, computes the expected
NSEC3 hashes, and measures the gap between NSEC3 owner and next hashed
owner. White lies produce a gap of exactly 2 (H-1 to H+1); pre-computed
chains produce gaps proportional to 1/N of the hash space.

By default, uses the local system resolver. Use --doh to query via
DNS-over-HTTPS to Cloudflare (or a custom server with --doh-server).
"""

import sys
import base64
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
import dns.dnssec

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"

HASH_BITS = 160  # SHA-1
HASH_MAX = 2 ** HASH_BITS
NXNAME_TYPE = 128

B32HEX_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUV"


def query_dns(qname, rdtype, doh_url=None):
    """Send a DNS query and return the response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags |= dns.flags.AD
    if doh_url:
        return dns.query.https(q, doh_url)
    resolver = dns.resolver.Resolver()
    return dns.query.udp(q, resolver.nameservers[0])


def random_label(length=10):
    """Generate a random lowercase label unlikely to exist."""
    return ''.join(random.choice(string.ascii_lowercase)
                   for _ in range(length))


_B32HEX_TO_B32 = str.maketrans(
    '0123456789ABCDEFGHIJKLMNOPQRSTUV',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
)

_B32_TO_B32HEX = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    '0123456789ABCDEFGHIJKLMNOPQRSTUV',
)


def b32hex_to_int(s):
    """Decode a base32hex string to an integer."""
    s = s.upper()
    padding = (8 - len(s) % 8) % 8
    data = s + '=' * padding
    if hasattr(base64, 'b32hexdecode'):
        raw = base64.b32hexdecode(data)
    else:
        raw = base64.b32decode(data.translate(_B32HEX_TO_B32))
    return int.from_bytes(raw, 'big')


def hash_gap(owner_hash, next_hash):
    """Compute the gap between two NSEC3 hashes (mod 2^160)."""
    o = b32hex_to_int(owner_hash)
    n = b32hex_to_int(next_hash)
    return (n - o) % HASH_MAX


def gap_description(gap):
    """Human-readable description of a hash gap."""
    if gap <= 2:
        return str(gap)
    pct = gap / HASH_MAX * 100
    if pct >= 0.01:
        return f"{pct:.4f}%"
    return f"{gap} ({pct:.2e}%)"


def check_dnssec_enabled(zone_name, doh_url):
    """Verify the zone has DNSSEC by looking for RRSIG in a SOA response."""
    response = query_dns(zone_name, "SOA", doh_url)
    if response.rcode() != dns.rcode.NOERROR:
        return False, "SOA query failed"
    has_rrsig = any(
        rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer
    )
    if not has_rrsig:
        return False, "No RRSIG in SOA response"
    return True, "DNSSEC enabled"


def get_nsec3param(zone_name, doh_url):
    """Fetch the NSEC3PARAM record for a zone.
    Returns (algorithm, flags, iterations, salt_hex) or None."""
    response = query_dns(zone_name, "NSEC3PARAM", doh_url)
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
            for rdata in rrset:
                salt_hex = rdata.salt.hex().upper() if rdata.salt else '-'
                return rdata.algorithm, rdata.flags, rdata.iterations, salt_hex
    return None


def bytes_to_b32hex(data):
    """Encode raw bytes as base32hex (no padding), uppercase."""
    if hasattr(base64, 'b32hexencode'):
        return base64.b32hexencode(data).decode().rstrip('=')
    return base64.b32encode(data).decode().translate(_B32_TO_B32HEX).rstrip('=')


def get_nsec3_records(response):
    """Extract NSEC3 records from the authority section.
    Returns list of (owner_hash, next_hash, types, rdata)."""
    records = []
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        owner_label = rrset.name.labels[0].decode().upper()
        for rdata in rrset:
            next_hash = bytes_to_b32hex(rdata.next)
            types = set()
            for window, bitmap in rdata.windows:
                for i, byte_val in enumerate(bitmap):
                    for bit in range(8):
                        if byte_val & (0x80 >> bit):
                            types.add(window * 256 + i * 8 + bit)
            records.append((owner_label, next_hash, types, rdata))
    return records


def get_nsec3_params_from_rdata(response):
    """Extract NSEC3 parameters (algorithm, iterations, salt) from
    an NSEC3 record in the authority section. The NSEC3PARAM RR at
    the apex can be stale during salt rotation; the parameters in
    the NSEC3 records themselves are always current."""
    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        for rdata in rrset:
            salt_hex = rdata.salt.hex().upper() if rdata.salt else '-'
            return rdata.algorithm, rdata.flags, rdata.iterations, salt_hex
    return None


def format_types(types):
    """Format a set of RR type numbers as a string."""
    if not types:
        return "(empty)"
    parts = []
    for t in sorted(types):
        try:
            parts.append(dns.rdatatype.to_text(t))
        except Exception:
            parts.append(f"TYPE{t}")
    return ' '.join(parts)


def nsec3_hash_name(name, salt_hex, iterations):
    """Compute the NSEC3 hash of a DNS name."""
    if salt_hex == '-' or salt_hex == '':
        salt = b''
    else:
        salt = bytes.fromhex(salt_hex)
    return dns.dnssec.nsec3_hash(name, salt, iterations, 'SHA1')


def classify_nsec3(qname, zone, nsec3_records, salt_hex, iterations,
                   verbose=False):
    """
    Classify the NSEC3 records in an NXDOMAIN response relative to qname.

    Identifies the three closest-encloser-proof roles:
      - closest encloser match (owner == H(CE))
      - next closer name cover (owner < H(NCN) < next)
      - wildcard cover (owner < H(*.CE) < next)

    Returns a dict with gap analysis for each role.
    """
    h_qname = nsec3_hash_name(qname, salt_hex, iterations)
    h_ce = nsec3_hash_name(zone, salt_hex, iterations)
    h_wildcard = nsec3_hash_name(
        dns.name.Name((b'*',) + zone.labels), salt_hex, iterations)

    result = {
        'h_qname': h_qname,
        'h_ce': h_ce,
        'h_wildcard': h_wildcard,
        'ncn': None,
        'ce': None,
        'wc': None,
    }

    for owner_hash, next_hash, types, rdata in nsec3_records:
        gap = hash_gap(owner_hash, next_hash)

        if owner_hash == h_ce:
            result['ce'] = {
                'owner': owner_hash, 'next': next_hash,
                'gap': gap, 'types': types,
            }
        else:
            h_qname_int = b32hex_to_int(h_qname)
            o_int = b32hex_to_int(owner_hash)
            n_int = b32hex_to_int(next_hash)
            covers_qname = (n_int - o_int) % HASH_MAX > 0 and \
                (h_qname_int - o_int) % HASH_MAX < (n_int - o_int) % HASH_MAX

            h_wc_int = b32hex_to_int(h_wildcard)
            covers_wc = (n_int - o_int) % HASH_MAX > 0 and \
                (h_wc_int - o_int) % HASH_MAX < (n_int - o_int) % HASH_MAX

            if covers_qname:
                result['ncn'] = {
                    'owner': owner_hash, 'next': next_hash,
                    'gap': gap, 'types': types,
                }
            elif covers_wc:
                result['wc'] = {
                    'owner': owner_hash, 'next': next_hash,
                    'gap': gap, 'types': types,
                }

    return result


def probe_zone(zone_name, doh_url, num_queries=5, verbose=False):
    """Probe the zone with random queries and classify NSEC3 responses.
    Extracts NSEC3 parameters (salt, iterations) from each response's
    NSEC3 records rather than relying on a fixed salt, since some zones
    rotate salts frequently.
    Returns (results, cdoe_results) where cdoe_results tracks possible
    Compact Denial of Existence with NSEC3 (RFC 9824 Section 4)."""
    results = []
    cdoe_results = []

    for i in range(num_queries):
        label = random_label(8 + i)
        qname = dns.name.from_text(f"{label}.{zone_name}")
        response = query_dns(qname, "A", doh_url)
        rcode = response.rcode()

        nsec3_recs = get_nsec3_records(response)
        if not nsec3_recs:
            if verbose:
                print(f"  {qname}: no NSEC3 records in response")
            continue

        params = get_nsec3_params_from_rdata(response)
        if not params:
            if verbose:
                print(f"  {qname}: could not extract NSEC3 params")
            continue
        _, _, iterations, salt_hex = params

        if rcode == dns.rcode.NXDOMAIN:
            info = classify_nsec3(qname, zone_name, nsec3_recs, salt_hex,
                                  iterations, verbose)
            info['qname'] = qname
            results.append(info)

        elif rcode == dns.rcode.NOERROR:
            has_answer = any(
                rrset.rdtype not in (dns.rdatatype.RRSIG,)
                for rrset in response.answer
            )
            if has_answer:
                h_qname = nsec3_hash_name(qname, salt_hex, iterations)
                info = {
                    'h_qname': h_qname, 'qname': qname,
                    'ncn': None, 'ce': None, 'wc': None,
                }
                for owner_hash, next_hash, types, rdata in nsec3_recs:
                    gap = hash_gap(owner_hash, next_hash)
                    info['ncn'] = {
                        'owner': owner_hash, 'next': next_hash,
                        'gap': gap, 'types': types,
                    }
                    break
                if info['ncn']:
                    results.append(info)
                    if verbose:
                        print(f"  {qname}: wildcard response, "
                              f"NCN gap={gap_description(info['ncn']['gap'])}")
            else:
                for owner_hash, next_hash, types, rdata in nsec3_recs:
                    cdoe_types = types - {dns.rdatatype.RRSIG, dns.rdatatype.NSEC3}
                    has_nxname = NXNAME_TYPE in cdoe_types
                    is_minimal = cdoe_types <= {NXNAME_TYPE}
                    if is_minimal:
                        gap = hash_gap(owner_hash, next_hash)
                        cdoe_results.append({
                            'qname': qname,
                            'owner': owner_hash, 'next': next_hash,
                            'gap': gap, 'types': types,
                            'has_nxname': has_nxname,
                        })
                        if verbose:
                            nxname_str = " with NXNAME" if has_nxname else ""
                            print(f"  {qname}: NODATA, NSEC3 bitmap "
                                  f"[{format_types(types)}]{nxname_str} "
                                  f"gap={gap_description(gap)}")
                    break
        else:
            if verbose:
                print(f"  {qname}: rcode {dns.rcode.to_text(rcode)} (skipping)")

    return results, cdoe_results


def detect(zone_str, doh_url=None, num_queries=5, verbose=False, epsilon=None):
    """Main detection routine."""
    zone_name = dns.name.from_text(zone_str)
    print(f"\nAnalyzing zone: {zone_name}")
    print("=" * 70)

    print("\n[1] Checking DNSSEC...")
    enabled, msg = check_dnssec_enabled(zone_name, doh_url)
    print(f"    {msg}")
    if not enabled:
        print("\nResult: INCONCLUSIVE -- DNSSEC not available")
        return None

    print("\n[2] Checking for NSEC3...")
    params = get_nsec3param(zone_name, doh_url)
    if not params:
        test_name = dns.name.from_text(f"{random_label()}.{zone_name}")
        response = query_dns(test_name, "A", doh_url)
        has_nsec = any(
            rrset.rdtype == dns.rdatatype.NSEC
            for rrset in response.authority
        )
        if has_nsec:
            print("    Zone uses NSEC, not NSEC3")
        else:
            print("    No NSEC3PARAM found")
        print("\nResult: NOT NSEC3")
        return None

    algo, flags, iterations, salt_hex = params
    print(f"    NSEC3PARAM: algorithm {algo}, flags {flags}, "
          f"iterations {iterations}, salt {salt_hex}")

    print(f"\n[3] Probing with {num_queries} random queries...")
    results, cdoe_results = probe_zone(zone_name, doh_url, num_queries, verbose)

    if cdoe_results and not results:
        nxname_count = sum(1 for r in cdoe_results if r['has_nxname'])
        print(f"\n{'=' * 70}")
        print(f"  Queries analyzed:   {len(cdoe_results)}")
        print(f"\n  All responses: NOERROR/NODATA with minimal NSEC3 bitmap")
        if nxname_count:
            print(f"  NXNAME (TYPE128) present in {nxname_count}/"
                  f"{len(cdoe_results)} responses")
        if verbose:
            for r in cdoe_results:
                nxname_str = " NXNAME" if r['has_nxname'] else ""
                print(f"    {r['qname']}: [{format_types(r['types'])}]"
                      f"  gap={gap_description(r['gap'])}")
        nxname_str = " with NXNAME" if nxname_count else " without NXNAME"
        print(f"\nResult: Compact Denial of Existence with NSEC3 "
              f"(RFC 9824 Section 4){nxname_str}")
        return "cdoe_nsec3"

    if not results:
        print("    No usable responses with NSEC3 records")
        print("\nResult: INCONCLUSIVE")
        return None

    if verbose:
        for r in results:
            print(f"\n  query: {r['qname']}")
            print(f"    H(qname)    = {r['h_qname']}")
            if r['ncn']:
                ncn = r['ncn']
                print(f"    NCN cover:    {ncn['owner']} -> {ncn['next']}"
                      f"  gap={gap_description(ncn['gap'])}")
            if r['ce']:
                ce = r['ce']
                print(f"    CE match:     {ce['owner']} -> {ce['next']}"
                      f"  gap={gap_description(ce['gap'])}"
                      f"  [{format_types(ce['types'])}]")
            if r['wc']:
                wc = r['wc']
                print(f"    WC cover:     {wc['owner']} -> {wc['next']}"
                      f"  gap={gap_description(wc['gap'])}")

    ncn_gaps = [r['ncn']['gap'] for r in results if r['ncn']]
    ce_gaps = [r['ce']['gap'] for r in results if r['ce']]
    wc_gaps = [r['wc']['gap'] for r in results if r['wc']]

    print(f"\n{'=' * 70}")
    print(f"  Queries analyzed:   {len(results)}")

    if ncn_gaps:
        print(f"\n  Next closer name covering NSEC3 gaps:")
        for i, gap in enumerate(ncn_gaps):
            print(f"    query {i+1}: {gap_description(gap)}")

    if ce_gaps:
        print(f"\n  Closest encloser NSEC3 gaps:")
        for i, gap in enumerate(ce_gaps):
            print(f"    query {i+1}: {gap_description(gap)}")

    if wc_gaps:
        print(f"\n  Wildcard covering NSEC3 gaps:")
        for i, gap in enumerate(wc_gaps):
            print(f"    query {i+1}: {gap_description(gap)}")

    cover_threshold = 2 * (epsilon or 1)
    match_threshold = epsilon or 1

    all_ncn_minimal = ncn_gaps and all(g <= cover_threshold for g in ncn_gaps)
    all_ce_minimal = ce_gaps and all(g <= match_threshold for g in ce_gaps)
    all_wc_minimal = not wc_gaps or all(g <= cover_threshold for g in wc_gaps)

    strict_ncn = ncn_gaps and all(g == 2 for g in ncn_gaps)
    strict_wc = not wc_gaps or all(g == 2 for g in wc_gaps)
    strict = strict_ncn and strict_wc

    all_ncn_large = ncn_gaps and all(g > 100 for g in ncn_gaps)

    print()
    if all_ncn_minimal and all_wc_minimal:
        if strict:
            variant = "(strict H-1/H+1 per RFC 7129)"
        else:
            variant = f"(epsilon={epsilon}, max covering gap={cover_threshold})"
        label = "with minimal CE" if all_ce_minimal else ""
        print(f"Result: NSEC3 White Lies detected {label}")
        print(f"  {variant}")
        return "white_lies"
    elif all_ncn_large:
        print("Result: Traditional (pre-computed) NSEC3")
        avg_pct = sum(ncn_gaps) / len(ncn_gaps) / HASH_MAX * 100
        print(f"  Average NCN gap: {avg_pct:.4f}% of hash space")
        return "precomputed"
    else:
        print("Result: NSEC3 (unable to determine pre-computed vs white lies)")
        return "unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Detect NSEC3 type: pre-computed or white lies")
    parser.add_argument("zones", nargs='*',
                        help="DNS zone name(s) to analyze")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="Read zone names from file (one per line)")
    parser.add_argument("-n", "--num-queries", type=int, default=5,
                        help="Number of probe queries (default: 5)")
    parser.add_argument("--epsilon", type=int, metavar="N",
                        help="Max hash distance for white lies detection "
                        "(default: 1, strict RFC 7129)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show per-query details")
    parser.add_argument("--doh", action="store_true",
                        help="Use DNS-over-HTTPS (default: Cloudflare)")
    parser.add_argument("--doh-server", metavar="URL",
                        help="DoH server URL (implies --doh)")
    args = parser.parse_args()

    doh_url = None
    if args.doh or args.doh_server:
        doh_url = args.doh_server or DEFAULT_DOH_URL

    zones = list(args.zones)
    if args.file:
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    zones.append(line)

    if not zones:
        parser.error("no zones specified (use positional args or -f FILE)")

    for zone in zones:
        if not zone.endswith('.'):
            zone += '.'
        try:
            detect(zone, doh_url, args.num_queries, args.verbose,
                   args.epsilon)
        except Exception as e:
            print(f"\nError analyzing {zone}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
