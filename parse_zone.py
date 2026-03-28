#!/usr/bin/env python3
"""
DNS Zone File Parser

A Python script that uses argparse to accept a DNS zone file argument
and provides basic functionality to read and parse the zone file.
"""

import argparse
import sys
import os
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple


__version__ = "0.1.0"


@dataclass
class FilterConfig:
    """Configuration for DNS record filtering."""
    no_dnssec: bool = False
    rrtypes: str = None
    includename: str = None
    includedata: str = None
    excludename: str = None
    excludedata: str = None
    wildcard: bool = False
    ttl_min: int = None
    ttl_max: int = None
    class_filter: str = None
    delegations: bool = False
    regex: bool = False
    minlabelcount: int = None
    maxlabelcount: int = None


# DNSSEC record types to exclude when without_dnssec is True
DNSSEC_TYPES = {'DNSKEY', 'DS', 'NSEC3PARAM', 'NSEC3', 'NSEC', 'RRSIG'}

# DNS record classes
DNS_CLASSES = {'IN', 'CH', 'CS', 'HS', 'ANY'}

# TTL unit multipliers (BIND-style)
TTL_MULTIPLIERS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}


def parse_ttl(value: str) -> Optional[int]:
    """
    Parse a TTL value, handling BIND-style unit suffixes (s, m, h, d, w).

    Examples: "3600", "1h", "1h30m", "1d", "2w"

    Returns:
        int: TTL in seconds, or None if not a valid TTL
    """
    if not value or not value[0].isdigit():
        return None
    lower = value.lower()
    if lower.isdigit():
        return int(lower)
    total = 0
    current = 0
    for char in lower:
        if char.isdigit():
            current = current * 10 + int(char)
        elif char in TTL_MULTIPLIERS:
            total += current * TTL_MULTIPLIERS[char]
            current = 0
        else:
            return None
    # Trailing bare number treated as seconds
    total += current
    return total if total > 0 else None


def _find_comment(line: str) -> int:
    """Find the position of a comment (;) outside of double-quoted strings."""
    in_quote = False
    for i, char in enumerate(line):
        if char == '"':
            in_quote = not in_quote
        elif char == ';' and not in_quote:
            return i
    return -1


def include_record(record: Dict[str, Any], filters: FilterConfig, zone_origin: str = None) -> bool:
    """
    Determine if a DNS record should be included based on filter criteria.
    Args:
        record (Dict[str, Any]): DNS record dictionary with name, ttl, class, type, data
        filters (FilterConfig): Configuration for filtering records
        zone_origin (str): Zone origin name for delegation filtering

    Returns:
        bool: True if record should be included, False if it should be filtered out
    """

    if filters.no_dnssec and record['type'] in DNSSEC_TYPES:
        return False

    if filters.rrtypes:
        allowed_types = {rt.strip().upper() for rt in filters.rrtypes.split(',')}
        if record['type'] not in allowed_types:
            return False

    if filters.includename:
        if filters.regex:
            try:
                if not re.search(filters.includename, record['name'], re.IGNORECASE):
                    return False
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{filters.includename}': {e}",
                      file=sys.stderr)
                return False
        else:
            if filters.includename.lower() not in record['name'].lower():
                return False

    if filters.excludename:
        if filters.regex:
            try:
                if re.search(filters.excludename, record['name'], re.IGNORECASE):
                    return False
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{filters.excludename}': {e}",
                      file=sys.stderr)
                return False
        else:
            if filters.excludename.lower() in record['name'].lower():
                return False

    if filters.includedata:
        if filters.regex:
            try:
                if not re.search(filters.includedata, record['data'], re.IGNORECASE):
                    return False
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{filters.includedata}': {e}",
                      file=sys.stderr)
                return False
        else:
            if filters.includedata.lower() not in record['data'].lower():
                return False

    if filters.excludedata:
        if filters.regex:
            try:
                if re.search(filters.excludedata, record['data'], re.IGNORECASE):
                    return False
            except re.error as e:
                print(f"Warning: Invalid regex pattern '{filters.excludedata}': {e}",
                      file=sys.stderr)
                return False
        else:
            if filters.excludedata.lower() in record['data'].lower():
                return False

    if filters.wildcard and not record['name'].startswith('*.'):
        return False

    if filters.delegations:
        if record['type'] != 'NS':
            return False
        if zone_origin and record['name'] == zone_origin:
            return False

    if filters.ttl_min is not None or filters.ttl_max is not None:
        if record['ttl'] is None:
            return False
        if filters.ttl_min is not None and record['ttl'] < filters.ttl_min:
            return False
        if filters.ttl_max is not None and record['ttl'] > filters.ttl_max:
            return False

    if filters.class_filter and record['class'].upper() != filters.class_filter.upper():
        return False

    if filters.minlabelcount is not None or filters.maxlabelcount is not None:
        name = record['name']
        if name == '.':
            label_count = 1
        else:
            label_count = len(name.rstrip('.').split('.')) + 1
        if filters.minlabelcount is not None and label_count < filters.minlabelcount:
            return False
        if filters.maxlabelcount is not None and label_count > filters.maxlabelcount:
            return False

    return True


def parse_zonefile(filepath: str = None,
                   filters: FilterConfig = None) -> Tuple[List[Dict[str, Any]], int, str]:
    """
    Parse a DNS zone file and return a list of DNS records and count of skipped lines.

    Args:
        filepath (str): Path to the zone file (None to read from stdin)
        filters (FilterConfig): Configuration for filtering records

    Returns:
        tuple[List[Dict[str, Any]], int, str]: List of DNS records with their properties,
        count of skipped lines, and zone origin
    """

    if filters is None:
        filters = FilterConfig()

    records = []
    skipped_lines = 0

    try:
        if filepath is None:
            file = sys.stdin
        else:
            file = open(filepath, 'r', encoding='utf-8')
    except PermissionError:
        print(f"Error: Permission denied reading '{filepath}'.", file=sys.stderr)
        sys.exit(1)

    with file:
        current_origin = None
        current_ttl = None
        zone_origin = None
        first_soa_found = False
        previous_name = None
        in_parens = False
        accumulated_line = ''
        accumulated_line_num = 0
        accumulated_starts_with_space = False

        for line_num, raw_line in enumerate(file, 1):
            # Strip comments outside of quoted strings
            comment_pos = _find_comment(raw_line)
            if comment_pos >= 0:
                raw_line = raw_line[:comment_pos]

            stripped = raw_line.strip()
            if not stripped:
                if not in_parens:
                    skipped_lines += 1
                continue

            # Handle multi-line records (parenthesized groups)
            if in_parens:
                accumulated_line += ' ' + stripped.replace('(', '').replace(')', '')
                if ')' in stripped:
                    in_parens = False
                    line = accumulated_line.strip()
                    line_num = accumulated_line_num
                    starts_with_space = accumulated_starts_with_space
                else:
                    continue
            elif '(' in stripped:
                accumulated_starts_with_space = len(raw_line) > 0 and raw_line[0] in (' ', '\t')
                accumulated_line = stripped.replace('(', '').replace(')', '')
                accumulated_line_num = line_num
                if ')' in stripped:
                    # Opening and closing parens on same line
                    line = accumulated_line.strip()
                    starts_with_space = accumulated_starts_with_space
                else:
                    in_parens = True
                    continue
            else:
                line = stripped
                starts_with_space = len(raw_line) > 0 and raw_line[0] in (' ', '\t')

            # Process directives
            if line.startswith('$ORIGIN'):
                parts = line.split()
                if len(parts) >= 2:
                    current_origin = parts[1]
                    zone_origin = current_origin
                continue

            if line.startswith('$TTL'):
                parts = line.split()
                if len(parts) >= 2:
                    current_ttl = parse_ttl(parts[1])
                    if current_ttl is None:
                        print(f"Warning: Invalid $TTL value on line {line_num}: {parts[1]}",
                              file=sys.stderr)
                continue

            if line.startswith('$INCLUDE'):
                print(f"Warning: $INCLUDE directive on line {line_num} not supported, skipping.",
                      file=sys.stderr)
                skipped_lines += 1
                continue

            if line.startswith('$'):
                skipped_lines += 1
                continue

            try:
                parts = line.split()
                if len(parts) < 2:
                    print(f"Warning: Skipping malformed line {line_num}: {line}",
                          file=sys.stderr)
                    skipped_lines += 1
                    continue

                idx = 0

                # Determine owner name
                if starts_with_space:
                    name = previous_name
                    if name is None:
                        print(f"Warning: No previous owner name for line {line_num}: {line}",
                              file=sys.stderr)
                        skipped_lines += 1
                        continue
                else:
                    name = parts[0]
                    idx = 1

                # Parse optional TTL and class in either order (RFC 1035 allows both)
                ttl = None
                record_class = None
                for _ in range(2):
                    if idx >= len(parts):
                        break
                    token = parts[idx]
                    parsed = parse_ttl(token)
                    if parsed is not None and ttl is None:
                        ttl = parsed
                        idx += 1
                    elif token.upper() in DNS_CLASSES and record_class is None:
                        record_class = token.upper()
                        idx += 1
                    else:
                        break

                if ttl is None:
                    ttl = current_ttl
                if record_class is None:
                    record_class = 'IN'

                # Next field must be the record type
                if idx >= len(parts):
                    print(f"Warning: Skipping incomplete line {line_num}: {line}",
                          file=sys.stderr)
                    skipped_lines += 1
                    continue

                record_type = parts[idx].upper()
                idx += 1

                # Remaining fields are the record data
                data = ' '.join(parts[idx:])

                # Expand relative names
                if name == '@' and current_origin:
                    name = current_origin
                elif not name.endswith('.') and current_origin:
                    name = f"{name}.{current_origin}"

                previous_name = name

                # Determine zone origin from first SOA record if $ORIGIN not present
                if not first_soa_found and record_type == 'SOA':
                    if zone_origin is None:
                        zone_origin = name
                    first_soa_found = True

                record = {
                    'name': name,
                    'ttl': ttl,
                    'class': record_class,
                    'type': record_type,
                    'data': data,
                    'line': line_num
                }

                if include_record(record, filters, zone_origin):
                    records.append(record)
                else:
                    skipped_lines += 1

            # pylint: disable=broad-except
            except Exception as e:
                print(f"Error parsing line {line_num}: {line}", file=sys.stderr)
                print(f"Error details: {e}", file=sys.stderr)
                skipped_lines += 1
                continue

    return records, skipped_lines, zone_origin


def print_records(records: List[Dict[str, Any]]) -> None:
    """
    Print DNS records in a formatted way.

    Args:
        records (List[Dict[str, Any]]): List of DNS records to print
    """
    if not records:
        print("No DNS records found in the zone file.")
        return

    for record in records:
        name = record['name']
        ttl = str(record['ttl']) if record['ttl'] is not None else 'N/A'
        record_class = record['class'] if record['class'] else 'N/A'
        record_type = record['type'] if record['type'] else 'N/A'
        data = record['data']

        print(f"{name:<30} {ttl:<8} {record_class:<4} {record_type:<8} {data}")


def print_statistics(records: List[Dict[str, Any]],
                     skipped_lines: int = 0,
                     zone_origin: str = None) -> None:
    """
    Print DNS record type statistics.

    Args:
        records (List[Dict[str, Any]]): List of DNS records to analyze
        skipped_lines (int): Number of lines that were skipped during parsing
        zone_origin (str): Zone origin name for delegation counting
    """
    print("### DNS Zone Statistics:")

    if zone_origin:
        print(f"### Zone: {zone_origin}\n")

    if not records:
        print("No DNS records found to analyze.")
        if skipped_lines > 0:
            print(f"Lines skipped during parsing: {skipped_lines}")
        return

    print(f"{'Records:':<12} {len(records):>8}")
    if skipped_lines > 0:
        print(f"Lines skipped during parsing: {skipped_lines}")

    # Calculate RRsets (records with same name, class, and type)
    rrsets = {}
    for record in records:
        key = (record['name'], record['class'], record['type'])
        if key not in rrsets:
            rrsets[key] = []
        rrsets[key].append(record)

    print(f"{'RRsets:':<12} {len(rrsets):>8}")

    # Count distinct names
    distinct_names = {record['name'] for record in records}
    print(f"{'Names:':<12} {len(distinct_names):>8}")

    # Count wildcard records
    wildcard_count = sum(1 for record in records if record['name'].startswith('*.'))
    if wildcard_count > 0:
        print(f"{'Wildcards:':<12} {wildcard_count:>8}")

    # Count delegation records (unique names for NS records that are not for zone origin)
    delegation_names = {record['name'] for record in records
                       if record['type'] == 'NS' and record['name'] != zone_origin}
    if delegation_names:
        print(f"{'Delegations:':<12} {len(delegation_names):>8}")

    # Count record types
    record_types = {}
    for record in records:
        record_type = record['type']
        record_types[record_type] = record_types.get(record_type, 0) + 1

    # Count RRsets by type
    rrsets_by_type = {}
    for key, _ in rrsets.items():
        record_type = key[2]  # type is the third element in the key tuple
        rrsets_by_type[record_type] = rrsets_by_type.get(record_type, 0) + 1

    print("\nRecord type statistics:")
    print(f"{'Type':<10} {'RR':>8} {'RR%':>11} {'RRsets':>9} {'RRset%':>9}")
    print("-" * 51)

    total_records = len(records)
    total_rrsets = len(rrsets)
    for record_type, count in sorted(record_types.items()):
        percentage = (count / total_records) * 100
        rrset_count = rrsets_by_type.get(record_type, 0)
        rrset_percentage = (rrset_count / total_rrsets) * 100 if total_rrsets > 0 else 0
        print(f"{record_type:<10} {count:>8} {percentage:>10.1f}% "
              f"{rrset_count:>9} {rrset_percentage:>8.1f}%")


def get_args():
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(
        description="Parse and display DNS zone file information",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('zonefile', nargs='?',
                        help='Path to DNS zone file (read stdin if not provided)')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--printrecords', action='store_true',
                        help='Print the (relevant) DNS records in the zone')
    parser.add_argument('--stats', action='store_true',
                        help='Print DNS record type statistics')
    parser.add_argument('--no-dnssec', action='store_true',
                        help='Exclude DNSSEC-related records')
    parser.add_argument('--rrtypes', type=str, metavar='TYPES',
                        help='Comma-separated list of record types to include (e.g., A,AAAA,MX)')
    parser.add_argument('--includename', type=str, metavar='NAME',
                        help='Include records with names containing string (case insensitive)')
    parser.add_argument('--includedata', type=str, metavar='DATA',
                        help='Include records with data containing string (case insensitive)')
    parser.add_argument('--excludename', type=str, metavar='NAME',
                        help='Exclude records with names containing string (case insensitive)')
    parser.add_argument('--excludedata', type=str, metavar='DATA',
                        help='Exclude records with data containing string (case insensitive)')
    parser.add_argument('--regex', action='store_true',
                        help='Treat --include*/--exclude* filter values as regex patterns')
    parser.add_argument('--wildcard', action='store_true',
                        help='Only process wildcard DNS records (names starting with *.')
    parser.add_argument('--delegations', action='store_true',
                        help='Only process delegation records (NS records not for zone origin)')
    parser.add_argument('--ttl-min', type=int, metavar='TTL',
                        help='Minimum TTL value (inclusive) for filtering records')
    parser.add_argument('--ttl-max', type=int, metavar='TTL',
                        help='Maximum TTL value (inclusive) for filtering records')
    parser.add_argument('--class', type=str, metavar='CLASS', dest='class_filter',
                        help='Filter records by class (e.g., IN, CH, HS)')
    parser.add_argument('--minlabelcount', type=int, metavar='N',
                        help='Only include records whose owner name has at least N labels '
                             '(including the root label, e.g. "www.example.com." has 4)')
    parser.add_argument('--maxlabelcount', type=int, metavar='N',
                        help='Only include records whose owner name has at most N labels '
                             '(including the root label, e.g. "example.com." has 3)')
    return parser.parse_args()


def main():
    """Main function to handle command line arguments and process the zone file."""
    args = get_args()

    if args.zonefile and not os.path.isfile(args.zonefile):
        print(f"Error: '{args.zonefile}' is not a file.", file=sys.stderr)
        sys.exit(1)

    if (args.minlabelcount is not None and args.maxlabelcount is not None
            and args.minlabelcount > args.maxlabelcount):
        print("Error: --minlabelcount cannot be greater than --maxlabelcount.",
              file=sys.stderr)
        sys.exit(1)

    filters = FilterConfig(
        no_dnssec=args.no_dnssec,
        rrtypes=args.rrtypes,
        includename=args.includename,
        includedata=args.includedata,
        excludename=args.excludename,
        excludedata=args.excludedata,
        wildcard=args.wildcard,
        delegations=args.delegations,
        ttl_min=args.ttl_min,
        ttl_max=args.ttl_max,
        class_filter=args.class_filter,
        regex=args.regex,
        minlabelcount=args.minlabelcount,
        maxlabelcount=args.maxlabelcount
    )

    records, skipped_lines, zone_origin = parse_zonefile(filepath=args.zonefile, filters=filters)

    if args.printrecords:
        print_records(records)

    if args.stats:
        if args.printrecords:
            print('')
        print_statistics(records, skipped_lines, zone_origin=zone_origin)


if __name__ == "__main__":
    main()
