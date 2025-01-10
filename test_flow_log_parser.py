import unittest
import tempfile
import os
from flow_log_parser import FlowLogAnalyzer

class TestFlowLogAnalyzer(unittest.TestCase):
    def setUp(self):
        """Set up test files and environment before each test."""

        self.temp_dir = tempfile.mkdtemp()
        

        self.lookup_file = os.path.join(self.temp_dir, "test_lookup.csv")
        with open(self.lookup_file, "w") as f:
            f.write("dstport,protocol,tag\n")
            f.write("443,tcp,sv_P2\n")
            f.write("23,tcp,sv_P1\n")
            f.write("25,tcp,sv_P1\n")
            f.write("110,tcp,email\n")
            f.write("993,tcp,email\n")
            f.write("143,tcp,email\n")
        

        self.flow_log_file = os.path.join(self.temp_dir, "test_flow.log")
        with open(self.flow_log_file, "w") as f:
            # Valid entries
            f.write("2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK\n")
            f.write("2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 49154 23 6 15 12000 1620140761 1620140821 REJECT OK\n")
            f.write("2 123456789012 eni-5e6f7g8h 192.168.1.101 198.51.100.3 49155 25 6 10 8000 1620140761 1620140821 ACCEPT OK\n")
            
        self.output_file = os.path.join(self.temp_dir, "test_output.csv")
        
        self.protocol_file = os.path.join(self.temp_dir, "protocol_mappings.csv")
        with open(self.protocol_file, "w") as f:
            f.write("protocol_number,protocol_name,description\n")
            f.write("6,tcp,Transmission Control Protocol\n")
            f.write("17,udp,User Datagram Protocol\n")
            f.write("1,icmp,Internet Control Message Protocol\n")

        if os.path.exists("protocol_mappings.csv"):
            os.rename("protocol_mappings.csv", "protocol_mappings.csv.bak")
        os.link(self.protocol_file, "protocol_mappings.csv")
        
        self.analyzer = FlowLogAnalyzer(self.lookup_file, self.flow_log_file, self.output_file)

    def tearDown(self):
        """Clean up test files after each test."""
        for file in [self.lookup_file, self.flow_log_file, self.output_file, 
                    self.protocol_file, "protocol_mappings.csv"]:
            if os.path.exists(file):
                os.remove(file)
        
        # Restore original protocol mappings file if it existed
        if os.path.exists("protocol_mappings.csv.bak"):
            os.rename("protocol_mappings.csv.bak", "protocol_mappings.csv")
    
        os.rmdir(self.temp_dir)

    ##TEST CASES

    # Test1 : Testing different protocol normalization with different format
    def test_normalize_protocol(self):
        self.assertEqual(self.analyzer._normalize_protocol("TCP"), "tcp")
        self.assertEqual(self.analyzer._normalize_protocol("6"), "tcp")
        self.assertEqual(self.analyzer._normalize_protocol("17"), "udp")
        self.assertEqual(self.analyzer._normalize_protocol("udp"), "udp")

    #Test2 : Test for correct parsing of Log Lines 
    def test_parse_flow_log_line(self):

        #Valid line
        line = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK"
        dst_port, protocol = self.analyzer._parse_flow_log_line(line)
        self.assertEqual(dst_port, 49153)
        self.assertEqual(protocol, "tcp")

    #Test3 : Test for valid log line
    def test_minimum_fields_requirement(self):
        """Test the minimum fields requirement (14) for flow log lines."""
        # Test with less than 14 fields
        insufficient_fields = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761"
        with self.assertRaises(ValueError) as context:
            self.analyzer._parse_flow_log_line(insufficient_fields)
        self.assertIn(f"Line has insufficient fields", str(context.exception))
        self.assertIn("minimum required: 14", str(context.exception))

        # Test with exactly 14 fields
        exact_fields = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 49153 443 6 25 20000 1620140761 1620140821 ACCEPT OK"
        try:
            self.analyzer._parse_flow_log_line(exact_fields)
        except ValueError as e:
            self.fail(f"Valid 14-field format raised an exception: {e}")

        # Test with empty/whitespace line
        empty_line = "   "
        with self.assertRaises(ValueError) as context:
            self.analyzer._parse_flow_log_line(empty_line)
        self.assertIn("insufficient fields", str(context.exception))

        # Test with partial line
        partial_line = "2 123456789012"
        with self.assertRaises(ValueError) as context:
            self.analyzer._parse_flow_log_line(partial_line)
        self.assertIn("insufficient fields", str(context.exception))

    #Test4: Test for handling of invalid flow log version.
    def test_invalid_flow_log_version(self):
        line = "1 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK"
        with self.assertRaises(ValueError):
            self.analyzer._parse_flow_log_line(line)

    #Test5: Test for complete log analysis functionality. 
    def test_analyze_logs(self):
        tag_counts, combo_counts = self.analyzer.analyze_logs()
        
        print("\nDebug Information:")
        print("Tag Counts:", tag_counts)
        print("Combo Counts:", combo_counts)
        
        # Verifying tag counts
        self.assertEqual(tag_counts.get("sv_P1", 0), 2)  # 23 and 25 are tagged as sv_P1
        self.assertEqual(tag_counts.get("Untagged", 0), 0)  # 49153 is untagged
        
        # Verifying port/protocol combinations
        self.assertEqual(combo_counts.get((443, "tcp")), 1)
        self.assertEqual(combo_counts.get((23, "tcp")), 1)
        self.assertEqual(combo_counts.get((25, "tcp")), 1)

    #Test6 : Test for handling of invalid or missing files.
    def test_invalid_files(self):
        with self.assertRaises(Exception):
            FlowLogAnalyzer("nonexistent.csv", self.flow_log_file, self.output_file)

        analyzer = FlowLogAnalyzer(self.lookup_file, "nonexistent.log", self.output_file)
        with self.assertRaises(Exception):
            analyzer.analyze_logs()

    #Test7: Test for writing analysis results to file.
    def test_write_results(self):
        tag_counts = {"sv_P1": 2, "Untagged": 1}
        combo_counts = {(49153, "tcp"): 1, (23, "tcp"): 1, (25, "tcp"): 1}
        
        self.analyzer.write_results(tag_counts, combo_counts)
        
        # Verify output file exists and contains expected content
        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, 'r') as f:
            content = f.read()
            self.assertIn("Tag Counts:", content)
            self.assertIn("sv_P1,2", content)
            self.assertIn("Untagged,1", content)
            self.assertIn("Port/Protocol Combination Counts:", content)



if __name__ == '__main__':
    unittest.main(verbosity=2)