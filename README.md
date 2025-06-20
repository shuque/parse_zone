# DNS Zone File Parser

A Python script that parses and process a DNS master zone format file.

Note: this program was written by a series of (about 20) prompts to Cursor (an AI assisted code editor).

## Usage

### Basic Usage

```
$ ./parse_zone.py -h
usage: parse_zone.py [-h] [--printrecords] [--stats] [--no-dnssec]
                     [--rrtypes TYPES] [--includename NAME]
                     [--includedata DATA] [--excludename NAME]
                     [--excludedata DATA] [--wildcard] [--delegations]
                     [--ttl-min TTL] [--ttl-max TTL] [--class CLASS]
                     [zonefile]

Parse and display DNS zone file information

positional arguments:
  zonefile            Path to DNS zone file (read stdin if not provided)

options:
  -h, --help          show this help message and exit
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
  --wildcard          Only process wildcard DNS records (names starting with
                      *.
  --delegations       Only process delegation records (NS records not for zone
                      origin)
  --ttl-min TTL       Minimum TTL value (inclusive) for filtering records
  --ttl-max TTL       Maximum TTL value (inclusive) for filtering records
  --class CLASS       Filter records by class (e.g., IN, CH, HS)
```

### Examples

```bash
# Parse a zone file silently (default behavior)
python3 parse_zone.py example.zone

# Print DNS records in formatted table
python3 parse_zone.py example.zone --printrecords

# Print record type statistics
python3 parse_zone.py example.zone --stats

# Print records with statistics
python3 parse_zone.py example.zone --printrecords --stats

# Only count records
python3 parse_zone.py example.zone --count-only

# Get help
python3 parse_zone.py --help
```

## Example Zone File

See `example.zone` for a sample DNS zone file that demonstrates various record types and formats.
