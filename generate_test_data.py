import random
import csv
import string
import time
from typing import List, Tuple
import os

class FlowLogGenerator:
    def __init__(self):
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        self.all_ports = self.common_ports + list(range(1024, 65535))

        self.protocols = ['6', '17', '1']

        self.service_tags = [
            'web', 'email', 'dns', 'db', 'ssh', 'ftp', 'telnet', 
            'rdp', 'vpn', 'storage', 'cache', 'auth', 'monitoring',
            'backup', 'streaming', 'gaming', 'api', 'proxy'
        ]

    def generate_random_ip(self) -> str:
        return f"{random.randint(1,255)}.{random.randint(0,255)}." \
               f"{random.randint(0,255)}.{random.randint(0,255)}"

    def generate_random_eni(self) -> str:
        return f"eni-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"

    def generate_lookup_table(self, num_entries: int, output_file: str) -> None:
        print(f"Generating lookup table with {num_entries} entries...")
        start_time = time.time()
        
        used_combinations = set()
        entries = []
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['dstport', 'protocol', 'tag'])
            
            for port in self.common_ports:
                for protocol in self.protocols:
                    if len(entries) < num_entries:
                        combo = (port, protocol)
                        if combo not in used_combinations:
                            tag = f"sv_{random.choice(self.service_tags)}"
                            entries.append([port, protocol, tag])
                            used_combinations.add(combo)

            while len(entries) < num_entries:
                port = random.choice(self.all_ports)
                protocol = random.choice(self.protocols)
                combo = (port, protocol)
                
                if combo not in used_combinations:
                    tag = f"sv_{random.choice(self.service_tags)}"
                    entries.append([port, protocol, tag])
                    used_combinations.add(combo)
            
            writer.writerows(entries)
        
        print(f"Lookup table generated in {time.time() - start_time:.2f} seconds")

    def generate_flow_log(self, min_size_mb: int, output_file: str) -> None:
        """
        Generate a flow log file of at least the specified size.
        Args:
            min_size_mb: Minimum file size in MB
            output_file: Output file path
        """
        print(f"Generating flow log of minimum {min_size_mb}MB...")
        start_time = time.time()
        min_size_bytes = min_size_mb * 1024 * 1024
        
        account_id = "123456789012"
        bytes_written = 0
        lines_written = 0
        
        with open(output_file, 'w') as f:
            while bytes_written < min_size_bytes:
                # Generate random flow log entry
                eni = self.generate_random_eni()
                src_ip = self.generate_random_ip()
                dst_ip = self.generate_random_ip()
                src_port = random.choice(self.all_ports)
                dst_port = random.randint(1024, 65535)
                protocol = random.choice(self.protocols)
                packets = random.randint(1, 1000)
                bytes_count = random.randint(64, 1500)
                start_time = int(time.time())
                end_time = start_time + random.randint(1, 300)
                action = random.choice(["ACCEPT", "REJECT"])
                
                # Create flow log entry
                line = f"2 {account_id} {eni} {src_ip} {dst_ip} {src_port} {dst_port} " \
                      f"{protocol} {packets} {bytes_count} {start_time} {end_time} {action} OK\n"
                
                f.write(line)
                bytes_written += len(line.encode())
                lines_written += 1
                
                if lines_written % 10000 == 0:
                    print(f"Generated {lines_written} lines, {bytes_written/1024/1024:.2f}MB...")
        
        final_size_mb = bytes_written/1024/1024
        print(f"Flow log generated in {time.time() - start_time:.2f} seconds")
        print(f"Final size: {final_size_mb:.2f}MB")
        print(f"Total lines: {lines_written}")

def main():
    generator = FlowLogGenerator()
    
    generator.generate_lookup_table(
        num_entries=11000,
        output_file='large_lookup.csv'
    )
    
    generator.generate_flow_log(
        min_size_mb=12,
        output_file='large_flow_log_data.txt'
    )

    lookup_size = os.path.getsize('large_lookup.csv') / 1024 / 1024
    flow_size = os.path.getsize('large_flow_log_data.txt') / 1024 / 1024
    
    print("\nGenerated Files:")
    print(f"Lookup table size: {lookup_size:.2f}MB")
    print(f"Flow log size: {flow_size:.2f}MB")

if __name__ == '__main__':
    main()