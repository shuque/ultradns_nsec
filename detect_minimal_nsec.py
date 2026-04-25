#!/usr/bin/env python3

"""
Compute the distance between two DNS domain names in canonical order
(RFC 4034 Section 6.1) and detect minimally covering NSEC records
(RFC 4470) by measuring how closely NSEC boundaries track query names.

Two analysis modes:

  calc  - Compute the label-level distance between two specific names.

  probe - Query a zone with random names and analyze the NSEC records
          in responses. For each NSEC, measures both the label distance
          between endpoints and the prefix similarity between the NSEC
          labels and the query label. Epsilon functions produce NSEC
          boundaries that closely mirror the query name; static NSEC
          chains do not.
"""

import sys
import math
import string
import random
import argparse

import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.flags
import dns.resolver

MAX_LABEL_LEN = 63

DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"


def label_to_int(label_bytes):
    """Interpret a DNS label as a big-endian integer, padded to 63 bytes."""
    padded = label_bytes.ljust(MAX_LABEL_LEN, b'\x00')
    return int.from_bytes(padded, 'big')


def get_outermost_label(name, origin):
    """Get the first label below the origin (outermost from the zone)."""
    rel = name.relativize(origin)
    if rel.labels and rel.labels[-1]:
        return rel.labels[-1].lower()
    return b''


def find_closest_encloser(name1, name2, origin):
    """
    Find the closest encloser (deepest common ancestor) of two names
    within a zone. Returns the common parent as a dns.name, and the
    first label below it from each name.
    """
    rel1 = name1.relativize(origin)
    rel2 = name2.relativize(origin)
    labels1 = list(rel1.labels)
    labels2 = list(rel2.labels)

    common_suffix = []
    while (labels1 and labels2
           and labels1[-1].lower() == labels2[-1].lower()):
        common_suffix.insert(0, labels1.pop())
        labels2.pop()

    first_label1 = labels1[-1].lower() if labels1 else b''
    first_label2 = labels2[-1].lower() if labels2 else b''

    encloser_labels = tuple(common_suffix) + origin.labels
    encloser = dns.name.Name(encloser_labels)

    return encloser, first_label1, first_label2


def label_distance(name1, name2, origin):
    """
    Compute distance at the first diverging label level.

    Finds the closest encloser of the two names, extracts the first
    label below it from each name, and returns the absolute difference
    of those labels interpreted as big-endian integers.
    """
    _, l1, l2 = find_closest_encloser(name1, name2, origin)
    return abs(label_to_int(l2) - label_to_int(l1))


def log2_label_distance(name1, name2, origin):
    """Compute log2 of the label distance. Returns 0 if names are equal."""
    dist = label_distance(name1, name2, origin)
    if dist == 0:
        return 0.0
    return math.log2(dist)


def max_label_distance_bits():
    """Maximum possible label distance in bits."""
    return MAX_LABEL_LEN * 8


def prefix_match_length(label1, label2):
    """Number of leading bytes shared between two labels."""
    match = 0
    for i in range(min(len(label1), len(label2))):
        if label1[i] == label2[i]:
            match += 1
        else:
            break
    return match


def resolve_name(text, zone_str):
    """Resolve a name argument: if not absolute, treat as relative to zone."""
    if not text.endswith('.'):
        text = f"{text}.{zone_str}"
        if not text.endswith('.'):
            text += '.'
    return dns.name.from_text(text)


def query_dns(qname, rdtype, doh_url=None):
    """Send a DNS query and return the response."""
    q = dns.message.make_query(qname, rdtype, want_dnssec=True)
    q.flags |= dns.flags.AD
    if doh_url:
        return dns.query.https(q, doh_url)
    resolver = dns.resolver.Resolver()
    return dns.query.udp(q, resolver.nameservers[0])


def find_covering_nsec(qname, response, zone):
    """
    Find the NSEC that covers the queried name (not the wildcard NSEC).
    Returns (owner, next_name) or None.
    """
    q_label = get_outermost_label(qname, zone)
    q_int = label_to_int(q_label)

    for rrset in response.authority:
        if rrset.rdtype != dns.rdatatype.NSEC:
            continue
        for rdata in rrset:
            owner = rrset.name
            next_name = rdata.next

            if not (owner.is_subdomain(zone)
                    and next_name.is_subdomain(zone)):
                continue

            o_label = get_outermost_label(owner, zone)
            n_label = get_outermost_label(next_name, zone)
            o_int = label_to_int(o_label)
            n_int = label_to_int(n_label)

            if o_int < n_int and o_int <= q_int <= n_int:
                return owner, next_name

    return None


def analyze_nsec(qname, owner, next_name, zone):
    """Analyze an NSEC pair relative to the query name."""
    q_label = get_outermost_label(qname, zone)
    o_label = get_outermost_label(owner, zone)
    n_label = get_outermost_label(next_name, zone)

    dist = abs(label_to_int(n_label) - label_to_int(o_label))
    dist_bits = math.log2(dist) if dist > 0 else 0

    owner_prefix = prefix_match_length(q_label, o_label)
    next_prefix = prefix_match_length(q_label, n_label)

    q_len = len(q_label)
    owner_ratio = owner_prefix / q_len if q_len > 0 else 0
    next_ratio = next_prefix / q_len if q_len > 0 else 0

    return {
        'q_label': q_label,
        'o_label': o_label,
        'n_label': n_label,
        'dist_bits': dist_bits,
        'owner_prefix': owner_prefix,
        'next_prefix': next_prefix,
        'owner_ratio': owner_ratio,
        'next_ratio': next_ratio,
        'q_len': q_len,
    }


def probe_zone(zone_str, doh_url=None, num_queries=5, verbose=False):
    """Query a zone for NSEC records and analyze them."""
    zone = dns.name.from_text(zone_str)
    results = []

    for i in range(num_queries):
        label = ''.join(random.choice(string.ascii_lowercase)
                        for _ in range(8 + i))
        qname = dns.name.from_text(f"{label}.{zone_str}")
        response = query_dns(qname, "A", doh_url)

        q_label = get_outermost_label(qname, zone)
        best = None
        best_prefix = -1

        for rrset in response.authority:
            if rrset.rdtype != dns.rdatatype.NSEC:
                continue
            for rdata in rrset:
                owner = rrset.name
                next_name = rdata.next
                if not (owner.is_subdomain(zone)
                        and next_name.is_subdomain(zone)):
                    continue
                n_label = get_outermost_label(next_name, zone)
                pfx = prefix_match_length(q_label, n_label)
                if pfx > best_prefix:
                    best_prefix = pfx
                    best = (owner, next_name)

        if best is None:
            if verbose:
                print(f"  [skip] {qname}: no in-zone NSEC found")
            continue

        owner, next_name = best
        info = analyze_nsec(qname, owner, next_name, zone)
        info['owner'] = owner
        info['next'] = next_name
        info['qname'] = qname
        results.append(info)

    return results


def cmd_calc(args):
    """Handle the 'calc' subcommand."""
    zone_str = args.zone
    if not zone_str.endswith('.'):
        zone_str += '.'
    zone = dns.name.from_text(zone_str)
    name1 = resolve_name(args.name1, zone_str)
    name2 = resolve_name(args.name2, zone_str)

    max_bits = max_label_distance_bits()

    print(f"Zone:             {zone}")
    print(f"NSEC owner:       {name1}")
    print(f"NSEC next:        {name2}")

    encloser, l1, l2 = find_closest_encloser(name1, name2, zone)
    dist = abs(label_to_int(l2) - label_to_int(l1))
    bits = math.log2(dist) if dist > 0 else 0

    print(f"Closest encloser: {encloser}")
    print(f"Diverging labels: {l1.decode(errors='replace')}"
          f" vs {l2.decode(errors='replace')}")
    print(f"Label distance:   2^{bits:.1f} ({bits:.2f} / {max_bits} bits)")

    if args.qname:
        qname = resolve_name(args.qname, zone_str)
        info = analyze_nsec(qname, name1, name2, zone)

        print(f"\nQuery name:       {qname}")
        print(f"Query label:      {info['q_label'].decode(errors='replace')}")
        print(f"Prefix match:     owner={info['owner_prefix']}"
              f"/{info['q_len']} ({info['owner_ratio']:.0%})"
              f"  next={info['next_prefix']}"
              f"/{info['q_len']} ({info['next_ratio']:.0%})")

        if info['next_ratio'] >= 0.75 and info['owner_ratio'] >= 0.5:
            print(f"\n  => NSEC boundaries track the query name")
            print(f"     Consistent with minimally covering NSEC"
                  f" (epsilon function)")
        elif info['next_ratio'] >= 0.5:
            print(f"\n  => NSEC boundaries partially track the query name")
            print(f"     Possibly minimally covering NSEC")
        else:
            print(f"\n  => NSEC boundaries do not track the query name")
            print(f"     Consistent with static/pre-signed NSEC chain")
    else:
        print(f"\nNote: use --qname to enable prefix similarity analysis")


def cmd_probe(args):
    """Handle the 'probe' subcommand."""
    zone_str = args.zone
    if not zone_str.endswith('.'):
        zone_str += '.'

    doh_url = None
    if args.doh or args.doh_server:
        doh_url = args.doh_server or DEFAULT_DOH_URL

    max_bits = max_label_distance_bits()

    print(f"Probing zone: {zone_str}")
    print(f"{'=' * 70}")

    results = probe_zone(zone_str, doh_url, args.num_queries,
                         verbose=args.verbose)

    if not results:
        print("No NSEC records found (zone may use NSEC3)")
        return

    for r in results:
        print(f"  query: {r['qname']}")
        print(f"    NSEC: {r['owner']} -> {r['next']}")
        print(f"    labels: {r['o_label'].decode(errors='replace')}"
              f" -> {r['n_label'].decode(errors='replace')}"
              f"  (query: {r['q_label'].decode(errors='replace')})")
        print(f"    label distance: {r['dist_bits']:.1f} / {max_bits} bits")
        print(f"    prefix match: owner={r['owner_prefix']}"
              f"/{r['q_len']} ({r['owner_ratio']:.0%})"
              f"  next={r['next_prefix']}"
              f"/{r['q_len']} ({r['next_ratio']:.0%})")

    next_ratios = [r['next_ratio'] for r in results]
    owner_ratios = [r['owner_ratio'] for r in results]
    dist_values = [r['dist_bits'] for r in results]

    avg_next = sum(next_ratios) / len(next_ratios)
    avg_owner = sum(owner_ratios) / len(owner_ratios)
    min_next = min(next_ratios)
    avg_dist = sum(dist_values) / len(dist_values)

    print(f"\n{'=' * 70}")
    print(f"  NSEC pairs analyzed:  {len(results)}")
    print(f"  Avg label distance:   {avg_dist:.1f} / {max_bits} bits")
    print(f"  Avg prefix match:     owner={avg_owner:.0%}  next={avg_next:.0%}")
    print(f"  Min next prefix:      {min_next:.0%}")

    if min_next >= 0.75 and avg_owner >= 0.5:
        print(f"\n  => NSEC boundaries consistently track query names")
        print(f"     Likely minimally covering NSEC (epsilon function)")
    elif min_next >= 0.5:
        print(f"\n  => NSEC boundaries partially track query names")
        print(f"     Possibly minimally covering NSEC")
    else:
        print(f"\n  => NSEC boundaries do not track query names")
        print(f"     Likely static/pre-signed NSEC chain")


def main():
    parser = argparse.ArgumentParser(
        description="Compute distance between DNS names in canonical order"
        " and detect minimally covering NSEC records")

    subparsers = parser.add_subparsers(dest="command")

    calc_p = subparsers.add_parser(
        "calc", help="Analyze an NSEC pair")
    calc_p.add_argument("zone", help="Zone (origin) name")
    calc_p.add_argument("name1", help="NSEC owner name (relative or absolute)")
    calc_p.add_argument("name2", help="NSEC next name (relative or absolute)")
    calc_p.add_argument("--qname", metavar="NAME",
                        help="Query name that produced this NSEC"
                        " (enables prefix similarity analysis)")

    probe_p = subparsers.add_parser(
        "probe", help="Query zone and measure NSEC distances")
    probe_p.add_argument("zone", help="Zone name to probe")
    probe_p.add_argument("-n", "--num-queries", type=int, default=5,
                         help="Number of queries (default: 5)")
    probe_p.add_argument("-v", "--verbose", action="store_true",
                         help="Show skipped NSEC pairs")
    probe_p.add_argument("--doh", action="store_true",
                         help="Use DNS-over-HTTPS (Cloudflare)")
    probe_p.add_argument("--doh-server", metavar="URL",
                         help="DoH server URL (implies --doh)")

    args = parser.parse_args()

    if args.command == "calc":
        cmd_calc(args)
    elif args.command == "probe":
        cmd_probe(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
