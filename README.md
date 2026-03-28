# DNS Zone File Parser

A Python script that parses and analyzes DNS master zone format files.
It can print records in a formatted table, display zone statistics,
and filter records by a variety of criteria.

Requires Python 3.9 or later. No external dependencies.

## Installation

The script can be run directly or installed via pip.

### Run directly

```bash
git clone https://github.com/shuque/parse_zone.git
cd parse_zone
./parse_zone.py --help
```

### Install with pip

```bash
pip install git+https://github.com/shuque/parse_zone.git
```

Or from a local checkout:

```bash
git clone https://github.com/shuque/parse_zone.git
cd parse_zone
pip install .
```

This installs `parse_zone.py` as a script on your PATH.

## Features

- Parses standard DNS master zone file format (RFC 1035)
- Handles multi-line records (parenthesized groups)
- Supports BIND-style TTL suffixes (`s`, `m`, `h`, `d`, `w`, e.g. `1h30m`)
- Processes `$ORIGIN` and `$TTL` directives
- Handles continuation lines (leading whitespace inherits previous owner name)
- Accepts TTL and class fields in either order
- Reads from a file or standard input

## Usage

```
$ ./parse_zone.py -h
usage: parse_zone.py [-h] [--version] [--printrecords] [--stats] [--no-dnssec]
                     [--rrtypes TYPES] [--includename NAME]
                     [--includedata DATA] [--excludename NAME]
                     [--excludedata DATA] [--regex] [--wildcard]
                     [--delegations] [--ttl-min TTL] [--ttl-max TTL]
                     [--class CLASS] [--minlabelcount N] [--maxlabelcount N]
                     [zonefile]

Parse and display DNS zone file information

positional arguments:
  zonefile            Path to DNS zone file (read stdin if not provided)

options:
  -h, --help          show this help message and exit
  --version           show program's version number and exit
  --printrecords      Print the (relevant) DNS records in the zone
  --stats             Print DNS record type statistics
  --no-dnssec         Exclude DNSSEC-related records
  --rrtypes TYPES     Comma-separated list of record types to include (e.g.,
                      A,AAAA,MX)
  --includename NAME  Include records with names containing string (case
                      insensitive)
  --includedata DATA  Include records with data containing string (case
                      insensitive)
  --excludename NAME  Exclude records with names containing string (case
                      insensitive)
  --excludedata DATA  Exclude records with data containing string (case
                      insensitive)
  --regex             Treat --include*/--exclude* filter values as regex
                      patterns
  --wildcard          Only process wildcard DNS records (names starting with
                      *.
  --delegations       Only process delegation records (NS records not for zone
                      origin)
  --ttl-min TTL       Minimum TTL value (inclusive) for filtering records
  --ttl-max TTL       Maximum TTL value (inclusive) for filtering records
  --class CLASS       Filter records by class (e.g., IN, CH, HS)
  --minlabelcount N   Only include records whose owner name has at least N
                      labels (including the root label, e.g. "www.example.com."
                      has 4)
  --maxlabelcount N   Only include records whose owner name has at most N
                      labels (including the root label, e.g. "example.com."
                      has 3)
```

## Examples

```bash
# Parse a zone file and print all records
./parse_zone.py example.zone --printrecords

# Print zone statistics
./parse_zone.py example.zone --stats

# Print records and statistics together
./parse_zone.py example.zone --printrecords --stats

# Read from stdin (e.g. after zone transfer)
dig axfr example.com @ns1.example.com | ./parse_zone.py --printrecords

# Show only A and AAAA records
./parse_zone.py example.zone --printrecords --rrtypes A,AAAA

# Exclude DNSSEC records from output
./parse_zone.py example.zone --printrecords --no-dnssec

# Filter by owner name substring
./parse_zone.py example.zone --printrecords --includename www

# Filter by owner name regex
./parse_zone.py example.zone --printrecords --regex --includename '^ns[0-9]'

# Exclude records whose data matches a regex
./parse_zone.py example.zone --printrecords --regex --excludedata '192\.168\.'

# Show only wildcard records
./parse_zone.py example.zone --printrecords --wildcard

# Show only delegation NS records (excluding zone apex)
./parse_zone.py example2.zone --printrecords --delegations

# Filter records by TTL range (in seconds)
./parse_zone.py example2.zone --printrecords --ttl-min 3600 --ttl-max 5400

# Filter by record class
./parse_zone.py example2.zone --printrecords --class CH

# Show only records with 4+ labels (one or more levels below zone apex)
./parse_zone.py example2.zone --printrecords --minlabelcount 4

# Show only zone apex records (exactly 3 labels for a .com zone)
./parse_zone.py example2.zone --printrecords --maxlabelcount 3

# Show records at exactly 4 labels deep
./parse_zone.py example2.zone --printrecords --minlabelcount 4 --maxlabelcount 4
```

## Filtering

Filters can be combined. When multiple filters are specified, all must
match for a record to be included (logical AND).

The `--includename`, `--includedata`, `--excludename`, and `--excludedata`
options perform case-insensitive substring matching by default. Use the
`--regex` flag to treat these values as regular expression patterns instead.

## Example Zone Files

- `example.zone` — basic zone file with common record types.
- `example2.zone` — exercises multi-line records, TTL suffixes, `$ORIGIN`
  changes, continuation lines, class/TTL field ordering, wildcard records,
  delegations, quoted TXT with embedded semicolons, and numeric owner names.
