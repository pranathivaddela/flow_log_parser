# Flow Log Analyzer

A Python-based tool for analyzing flow logs and mapping them to predefined tags based on port and protocol combinations.

## Problem Statement
Write a program that can parse a file containing flow log data and maps each row to a tag based on a lookup table.
<!-- Create a program that parses AWS VPC Flow Logs (Version 2) and maps each entry to specific tags based on a lookup table. The program should read port/protocol combinations from a CSV file, match them against the flow logs, and generate statistics about the matches. The implementation must handle files up to 10MB and support up to 10,000 tag mappings while using only Python standard libraries. -->

## Overview

The Flow Log Analyzer processes AWS VPC flow logs and maps each entry to tags based on destination port and protocol combinations. It supports custom tag mappings through a lookup file and provides detailed statistics about traffic patterns.

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
git clone <repository-url>
cd flow-log-analyzer
```

## Usage

```bash
python flow_log_analyzer.py <lookup_file> <flow_logs> <output_file>
```

### Parameters:
- `lookup_file`: CSV file containing port/protocol to tag mappings
- `flow_logs`: Flow log file to analyze
- `output_file`: Path where results will be written

### Example:
```bash
python flow_log_analyzer.py mappings.csv flow_logs.txt results.txt
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
Supports AWS VPC Flow Logs Version 2 format only. Example:
```
2 123456789012 eni-1234567890 10.0.1.4 10.0.2.5 443 49152 6 25 1800 1636375200 1636375300 ACCEPT OK
```

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

## Assumptions and Limitations

## Assumptions


1. Input Files:
   - All input files are ASCII text files
   - Files are well-formed (proper CSV format for lookup table)
   - Empty lines in flow logs are ignored

2. Protocol Handling:
   * Supports both protocol names (tcp, udp, icmp) and IANA protocol numbers
   * Protocol numbers are mapped according to IANA protocol number registry (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml):
      * 6 = tcp (Transmission Control Protocol)
      * 17 = udp (User Datagram Protocol)
      * 1 = icmp (Internet Control Message Protocol)
   * Protocol matching is case-insensitive

3. Tag Behavior:
   - Duplicate port/protocol combinations in lookup table are treated as errors
   - Empty or whitespace-only tags are not allowed
   - Missing tags are marked as "Untagged" in the output

4. Output Generation:
   - Tag counts and port/protocol counts are sorted in ascending order
   - Zero counts are included in the output
   - Output is in CSV format for easy parsing


## Testing

The project includes comprehensive test cases covering:
- Basic functionality
- Protocol normalization
- Tag mapping validation
- Error handling
- File Size verification
- Edge cases

To run tests:
```bash
python -m unittest test_flow_log_analyzer.py -v
```

## Performance Considerations
- Uses dictionary-based lookups for O(1) performance
- Processes files line by line to minimize memory usage
- Uses built-in Python libraries to avoid dependencies


