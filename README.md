# Flow Log Parser
A Python-based tool for parsing and analyzing AWS VPC Flow Logs and mapping them to predefined tags based on port and protocol combinations.

## Problem Statement
Write a program that can parse a file containing [flow log data](./flow_logs.txt) and maps each row to a tag based on a [lookup table](./lookup.csv).


## Overview

The Flow Log Parser processes AWS VPC flow logs and maps each entry to tags based on destination port and protocol combinations. It supports custom tag mappings through a lookup file and provides detailed statistics about traffic patterns.

## Features

- Parses AWS VPC Flow Logs (Version 2 format only)
- Maps traffic to tags based on port/protocol combinations
- Supports custom protocol mappings
- Supports up to 10,000 tag mappings
- Handles files up to 10MB in size
- Case-insensitive matching for protocols
- Comprehensive error handling and validation
- Generates detailed statistics in CSV format

## Requirements

- Python 3.6 or higher
- No external dependencies required

## Installation

1. Clone the repository:
```bash
git clone https://github.com/pranathivaddela/flow_log_parser.git
cd flow-log-parser
```

## Usage

```bash
python flow_log_parser.py <lookup_file> <flow_logs> <output_file>
```

### Parameters:
- `lookup_file`: CSV file containing port/protocol to tag mappings
- `flow_logs`: Flow log file to analyze
- `output_file`: Path where results will be written

### Example:
```bash
python flow_log_parser.py lookup.csv flow_logs.txt results.txt
```

## File Formats

### Lookup File Format (CSV):
```csv
dstport,protocol,tag
443,tcp,sv_P2
23,tcp,sv_P1
25,tcp,sv_P1
110,tcp,email
```

### Flow Log Format:
Supports AWS VPC Flow Logs Version 2 format only.
```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```
 Example:
```
2 123456789012 eni-1234567890 10.0.1.4 10.0.2.5 443 49152 6 25 1800 1636375200 1636375300 ACCEPT OK
```
Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html#flow-logs-default

### Output Format:
The tool generates a text file containing:
- Tag counts
- Port/protocol combination counts

Example output:
```
Tag Counts:
Tag,Count
sv_P2,10
sv_P1,5
email,3
Untagged,2

Port/Protocol Combination Counts:
Port,Protocol,Count
443,tcp,10
23,tcp,3
25,tcp,2
```
## Assumptions
1. Input Files:
   - All input files are ASCII text files
   - Files are well-formed (proper CSV format for lookup table)
   - Empty lines in flow logs are ignored

2. Protocol Handling:
   * Supports both protocol names (tcp, udp, icmp) and IANA protocol numbers
   * I have created a [protocol mapping file](./protocol_mappings.csv). Protocol numbers are mapped according to IANA protocol number registry (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). If the protocol file is not mentioned,it will consider the default dictionary mapping that I have defined:
      * 6 = tcp (Transmission Control Protocol)
      * 17 = udp (User Datagram Protocol)
      * 1 = icmp (Internet Control Message Protocol)
    
   * Protocol matching is case-insensitive
( Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html#flow-logs-fields )
3. Tag Behavior:
   - Duplicate port/protocol combinations in lookup table are treated as errors
   - Empty or whitespace-only tags are not allowed
   - Missing tags are marked as "Untagged" in the output

4. Output Generation:
   - Tag counts and port/protocol counts are sorted in ascending order
   - Zero counts are included in the output
   - Output is in CSV format for easy parsing


## Testing
This program allows do perform a comprehensive testing using Python's unittest framework.
To run tests:
```bash
python -m unittest test_flow_log_parser.py
```
### Test Coverage
The test suite covers:
- Protocol handling (mapping, fallback behavior, case sensitivity)
- Flow log parsing (valid and invalid formats)
- Analysis logic (tag counting, port/protocol combinations)
- File operations (missing/invalid files, output generation)
- Error conditions and edge cases

## Performance Considerations
- Uses dictionary-based lookups for O(1) performance
- Processes files line by line to minimize memory usage
- Uses built-in Python libraries to avoid dependencies

## Additional: Test Data Generator for Performance Testing

The project includes a [test data generator script](./generate_test_data.py) for performance testing. This 
- Generates realistic VPC Flow Log entries
- Creates lookup tables with configurable number of entries
- Produces files meeting size requirements (>10MB for logs, >10,000 entries for lookup)

### Usage
```bash
# Generate test data files
python generate_test_data.py
```

### Generated Files
1. Lookup Table (`large_lookup.csv`): Over 10,000 unique port/protocol combinations
2. Flow Logs (`large_flow_data_log.txt`): Over 10MB of valid VPC flow log data

### Customization
You can modify generation parameters in the script:
```python
# Generate larger test files
generator.generate_lookup_table(
    num_entries=20000,    # for more lookup entries
    output_file='large_lookup.csv'
)

generator.generate_flow_log(
    min_size_mb=50,       # for larger log file
    output_file='large_flow_data_log.txt'
)
```