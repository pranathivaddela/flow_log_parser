import csv
from collections import defaultdict
from typing import Dict, List, Tuple
import sys
import os

class FlowLogAnalyzer:
    # Default protocol mapping based on IANA protocol numbers
    DEFAULT_PROTOCOL_MAP = {
        '6': 'tcp',
        '17': 'udp',
        '1': 'icmp'    
    }

    # Minimum number of fields required in a valid flow log line
    MIN_FIELDS = 14

    def __init__(self, lookup_file: str, flow_log_file: str, output_file: str):
        self.lookup_file = lookup_file
        self.flow_log_file = flow_log_file
        self.output_file = output_file
        self.tag_mappings = {}
        self.protocol_map = self._load_protocol_mappings()
        self._load_lookup_file()

    def _load_protocol_mappings(self) -> Dict[str, str]:
        """
        Load protocol mappings from file if exists, else use default mapping.
        Returns:
            Dict[str, str]: Protocol mapping dictionary
        """
        protocol_file = 'protocol_mappings.csv'
        
        if os.path.exists(protocol_file):
            try:
                protocol_map = {}
                with open(protocol_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        protocol_map[row['protocol_number']] = row['protocol_name']
                        protocol_map[row['protocol_name']] = row['protocol_name']
                return protocol_map
            except Exception as e:
                print(f"Warning: Error reading protocol file: {e}. Using default mappings.")
                return self.DEFAULT_PROTOCOL_MAP
        return self.DEFAULT_PROTOCOL_MAP

    def _load_lookup_file(self) -> None:
        """Load and parse the port/protocol to tag lookup file."""
        try:
            with open(self.lookup_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    port = int(row['dstport'])
                    protocol = self._normalize_protocol(row['protocol'])
                    tag = row['tag']
                    self.tag_mappings[(port, protocol)] = tag
        except FileNotFoundError:
            raise Exception(f"Lookup file not found: {self.lookup_file}")
        except ValueError as e:
            raise Exception(f"Invalid data in lookup file: {str(e)}")

    def _normalize_protocol(self, protocol: str) -> str:
        """
        Normalize protocol string for consistent comparison.
        Args:
            protocol (str): Protocol string or number
        Returns:
            str: Normalized protocol name
        """
        return self.protocol_map.get(protocol.lower(), protocol.lower())

    def _parse_flow_log_line(self, line: str) -> Tuple[int, str]:
        """
        Parse a single flow log line.
        Args:
            line (str): Flow log line
        Returns:
            Tuple[int, str]: (destination_port, protocol)
        Raises:
            ValueError: If line format is invalid or missing required fields
        """
        fields = line.strip().split()
        
        if len(fields) < self.MIN_FIELDS:
            raise ValueError(f"Line has insufficient fields: {len(fields)}, minimum required: {self.MIN_FIELDS}")

        # Validating the version  
        if fields[0] != '2':
            raise ValueError("Only version 2 flow logs are supported")
            
        try:
            dst_port = int(fields[6])
            if dst_port < 0 or dst_port > 65535:
                raise ValueError(f"Invalid destination port number: {dst_port}")
                
            protocol = fields[7]
            if not protocol.isdigit() and protocol.lower() not in self.DEFAULT_PROTOCOL_MAP:
                raise ValueError(f"Unsupported protocol: {protocol}")
                
            return dst_port, self._normalize_protocol(protocol)
        except IndexError:
            raise ValueError(f"Invalid flow log line format: {line}")
        except ValueError as e:
            raise ValueError(f"Invalid field value: {str(e)}")

    def analyze_logs(self) -> Tuple[Dict[str, int], Dict[Tuple[int, str], int]]:
        """
        Analyze flow logs and generate statistics.
        Returns:
            Tuple[Dict[str, int], Dict[Tuple[int, str], int]]: 
            Tag counts and port/protocol combination counts
        """

        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
        # Verifying the file size
        file_size = os.path.getsize(self.flow_log_file)
        if file_size > MAX_FILE_SIZE:
            raise Exception(f"Flow log file exceeds maximum allowed size of 10MB (current size: {file_size/1024/1024:.2f}MB)")
        
        tag_counts = defaultdict(int)
        combo_counts = defaultdict(int)
        
        try:
            with open(self.flow_log_file, 'r') as f:
                for line in f:
                    try:
                        dst_port, protocol = self._parse_flow_log_line(line)
                        combo_counts[(dst_port, protocol)] += 1
                        tag = self.tag_mappings.get((dst_port, protocol), 'Untagged')
                        tag_counts[tag] += 1
                    except ValueError as e:
                        print(f"Warning: Skipping invalid line: {str(e)}", file=sys.stderr)
                        continue

            # print("Tag Counts:", tag_counts, "combocounts:", combo_counts)            
            return dict(tag_counts), dict(combo_counts)
            
        except FileNotFoundError:
            raise Exception(f"Flow log file not found: {self.flow_log_file}")

    def write_results(self, tag_counts: Dict[str, int], 
                     combo_counts: Dict[Tuple[int, str], int]) -> None:
        """Write analysis report for Tag count and Protocol Combination Counr"""
        try:
            with open(self.output_file, 'w', newline='') as f:
                f.write("Tag Counts:\n")
                f.write("Tag,Count\n")
                for tag, count in sorted(tag_counts.items()):
                    f.write(f"{tag},{count}\n")
                
                f.write("\nPort/Protocol Combination Counts:\n")
                f.write("Port,Protocol,Count\n")
                for (port, protocol), count in sorted(combo_counts.items()):
                    f.write(f"{port},{protocol},{count}\n")
                    
        except IOError as e:
            raise Exception(f"Error writing to output file: {str(e)}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python flow_log_analyzer.py <lookup_file> <flow_logs> <output_file>")
        sys.exit(1)

    lookup_file = sys.argv[1]
    flow_log_file = sys.argv[2]
    output_file = sys.argv[3]
    
    try:
        analyzer = FlowLogAnalyzer(lookup_file, flow_log_file, output_file)
        tag_counts, combo_counts = analyzer.analyze_logs()
        analyzer.write_results(tag_counts, combo_counts)
        print(f"Analysis complete. Results written to {output_file}")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()