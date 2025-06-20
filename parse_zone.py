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
from typing import List, Dict, Any


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


# DNSSEC record types to exclude when without_dnssec is True
DNSSEC_TYPES = {'DNSKEY', 'DS', 'NSEC3PARAM', 'NSEC3', 'NSEC', 'RRSIG'}


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
        if filters.includename.startswith('^'):
            # Regex matching
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
        if filters.excludename.startswith('^'):
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
        if filters.includedata.startswith('^'):
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
        if filters.excludedata.startswith('^'):
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

    try:
        ttl_value = int(record['ttl'])
        if filters.ttl_min is not None and ttl_value < filters.ttl_min:
            return False
        if filters.ttl_max is not None and ttl_value > filters.ttl_max:
            return False
    except (ValueError, TypeError):
        # If TTL can't be converted to int, skip the record
        return False

    if filters.class_filter and record['class'].upper() != filters.class_filter.upper():
        return False

    return True


def parse_zonefile(filepath: str = None,
                   filters: FilterConfig = None) -> tuple[List[Dict[str, Any]], int, str]:
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

        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line or line.startswith(';'):
                skipped_lines += 1
                continue

            if line.startswith('$ORIGIN'):
                current_origin = line.split()[1]
                zone_origin = current_origin
                continue

            if line.startswith('$TTL'):
                current_ttl = line.split()[1]
                continue

            try:
                parts = line.split()
                if len(parts) < 3:
                    print(f"Warning: Skipping malformed line {line_num}: {line}",
                          file=sys.stderr)
                    skipped_lines += 1
                    continue

                # Handle different record formats
                if parts[0].isdigit() or parts[0] == '@':
                    # Format: [name] [ttl] [class] [type] [data]
                    if len(parts) >= 4:
                        name = parts[0]
                        ttl = parts[1] if not parts[1].isalpha() else current_ttl
                        record_class = parts[1] if parts[1].isalpha() else parts[2]
                        record_type = parts[2] if parts[1].isalpha() else parts[3]
                        data = ' '.join(parts[3:] if parts[1].isalpha() else parts[4:])
                    else:
                        print(f"Warning: Skipping incomplete line {line_num}: {line}",
                              file=sys.stderr)
                        skipped_lines += 1
                        continue
                else:
                    # Format: [name] [class] [type] [data] or [name] [ttl] [class] [type] [data]
                    name = parts[0]
                    if len(parts) >= 4:
                        if parts[1].isdigit():
                            ttl = parts[1]
                            record_class = parts[2]
                            record_type = parts[3]
                            data = ' '.join(parts[4:])
                        else:
                            ttl = current_ttl
                            record_class = parts[1]
                            record_type = parts[2]
                            data = ' '.join(parts[3:])
                    else:
                        print(f"Warning: Skipping incomplete line {line_num}: {line}",
                              file=sys.stderr)
                        skipped_lines += 1
                        continue

                # Expand relative names
                if name == '@' and current_origin:
                    name = current_origin
                elif not name.endswith('.') and current_origin:
                    name = f"{name}.{current_origin}"

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
        ttl = str(record['ttl']) if record['ttl'] else 'N/A'
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
    return parser.parse_args()


def main():
    """Main function to handle command line arguments and process the zone file."""
    args = get_args()

    if args.zonefile and not os.path.isfile(args.zonefile):
        print(f"Error: '{args.zonefile}' is not a file.", file=sys.stderr)
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
        class_filter=args.class_filter
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
