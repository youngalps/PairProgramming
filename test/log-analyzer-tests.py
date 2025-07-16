"""
Modular Log Analyzer Test Suite

This test suite allows incremental testing of log analyzer features.
You can test individual sections as you build them.

Usage:
    python test_log_analyzer.py --all              # Run all tests
    python test_log_analyzer.py --parsing          # Test only parsing features
    python test_log_analyzer.py --filtering        # Test only filtering features
    python test_log_analyzer.py --analytics        # Test only analytics features
    python test_log_analyzer.py --patterns         # Test only pattern detection
    python test_log_analyzer.py --output           # Test only output features
    python test_log_analyzer.py --interface        # Test only CLI interface
    python test_log_analyzer.py --extensibility    # Test only extensibility features
"""

import unittest
import os
import json
import csv
import tempfile
import subprocess
import sys
import argparse
from datetime import datetime, timedelta
from io import StringIO


class BaseTestCase(unittest.TestCase):
    """Base test case with common setup and utilities."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures and sample data."""
        cls.sample_logs = [
            "2024-07-16 08:00:00 INFO [web] GET /health - 200 - 5ms - user_id=system",
            "2024-07-16 08:00:01 ERROR [db] Connection timeout - host=db-primary - timeout=5000ms",
            "2024-07-16 08:00:02 WARN [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:03 DEBUG [cache] Cache hit for key: user_profile_1001",
            "2024-07-16 08:00:04 INFO [web] GET /api/users/1001 - 200 - 1234ms - user_id=1001",
            "MALFORMED LOG LINE WITHOUT PROPER FORMAT",
            "2024-07-16 08:00:05 ERROR [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:06 ERROR [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:07 ERROR [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:08 ERROR [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:09 ERROR [auth] Failed login attempt - username=admin - ip=192.168.1.100",
            "2024-07-16 08:00:10 WARN [security] Brute force attack detected - ip=192.168.1.100",
            "2024-07-16 08:01:00 WARN [performance] Slow query detected - query=SELECT * FROM orders - duration=2345ms",
            "2024-07-16 08:02:00 ERROR [web] SQL injection attempt detected - ip=10.0.0.1 - payload='; DROP TABLE users;--",
            "2024-07-16 08:03:00 WARN [system] High memory usage - heap=4.2GB - threshold=4GB",
            "2024-07-16 08:04:00 ERROR [system] CPU usage critical - usage=95% - threshold=90%",
        ]
        
        # Create temporary test log file
        cls.test_log_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        cls.test_log_file.write('\n'.join(cls.sample_logs))
        cls.test_log_file.close()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test fixtures."""
        if hasattr(cls, 'test_log_file') and os.path.exists(cls.test_log_file.name):
            os.unlink(cls.test_log_file.name)
    
    def run_analyzer(self, *args):
        """Helper method to run the log analyzer with given arguments."""
        cmd = [sys.executable, 'main.py'] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result


class TestParsing(BaseTestCase):
    """Test parsing and data handling features."""
    
    def test_01_read_file_from_command_line(self):
        """Test that the analyzer can read log files from command line arguments."""
        print("\n✓ Testing: Read file from command line")
        result = self.run_analyzer(self.test_log_file.name)
        self.assertEqual(result.returncode, 0, "Analyzer should exit successfully")
        self.assertTrue(len(result.stdout) > 0, "Should produce some output")
    
    def test_02_parse_basic_log_structure(self):
        """Test basic parsing of timestamp, level, component, and message."""
        print("✓ Testing: Parse basic log structure")
        result = self.run_analyzer(self.test_log_file.name, '--show-parsed')
        self.assertEqual(result.returncode, 0)
        # Should show parsed elements
        self.assertIn("2024-07-16", result.stdout)
        self.assertIn("INFO", result.stdout)
        self.assertIn("[web]", result.stdout)
    
    def test_03_handle_malformed_lines(self):
        """Test that malformed log lines are handled gracefully."""
        print("✓ Testing: Handle malformed log lines")
        result = self.run_analyzer(self.test_log_file.name, '--show-malformed')
        self.assertEqual(result.returncode, 0)
        self.assertIn("MALFORMED", result.stdout, "Should report malformed lines")
    
    def test_04_stream_large_files(self):
        """Test that large files are processed efficiently."""
        print("✓ Testing: Stream large files efficiently")
        # Create a moderately sized test file
        large_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        for i in range(1000):
            large_file.write(f"2024-07-16 08:00:{i%60:02d} INFO [test] Test entry {i}\n")
        large_file.close()
        
        result = self.run_analyzer(large_file.name, '--count')
        self.assertEqual(result.returncode, 0)
        self.assertIn("1000", result.stdout, "Should count all entries")
        
        os.unlink(large_file.name)


class TestFiltering(BaseTestCase):
    """Test filtering capabilities."""
    
    def test_01_filter_by_level(self):
        """Test filtering by log level."""
        print("\n✓ Testing: Filter by log level")
        result = self.run_analyzer(self.test_log_file.name, '--level', 'ERROR')
        self.assertEqual(result.returncode, 0)
        output_lines = result.stdout.strip().split('\n')
        for line in output_lines:
            if line and not line.startswith('Found'):  # Skip summary lines
                self.assertIn("ERROR", line)
    
    def test_02_filter_by_component(self):
        """Test filtering by component."""
        print("✓ Testing: Filter by component")
        result = self.run_analyzer(self.test_log_file.name, '--component', 'auth')
        self.assertEqual(result.returncode, 0)
        output_lines = result.stdout.strip().split('\n')
        for line in output_lines:
            if line and not line.startswith('Found'):
                self.assertIn("[auth]", line)
    
    def test_03_filter_by_time_range(self):
        """Test filtering by time range."""
        print("✓ Testing: Filter by time range")
        result = self.run_analyzer(
            self.test_log_file.name,
            '--start-time', '2024-07-16 08:00:00',
            '--end-time', '2024-07-16 08:01:00'
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("08:02:00", result.stdout)
        self.assertNotIn("08:03:00", result.stdout)
    
    def test_04_chain_multiple_filters(self):
        """Test chaining multiple filters."""
        print("✓ Testing: Chain multiple filters")
        result = self.run_analyzer(
            self.test_log_file.name,
            '--level', 'ERROR',
            '--component', 'auth'
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Failed login attempt", result.stdout)
        self.assertNotIn("Connection timeout", result.stdout)


class TestAnalytics(BaseTestCase):
    """Test analysis and statistics features."""
    
    def test_01_count_by_level(self):
        """Test counting entries by log level."""
        print("\n✓ Testing: Count entries by level")
        result = self.run_analyzer(self.test_log_file.name, '--stats')
        self.assertEqual(result.returncode, 0)
        self.assertIn("ERROR", result.stdout)
        self.assertIn("WARN", result.stdout)
        self.assertIn("INFO", result.stdout)
        # Should show counts
        self.assertRegex(result.stdout, r'ERROR.*[0-9]+')
    
    def test_02_count_by_component(self):
        """Test counting entries by component."""
        print("✓ Testing: Count entries by component")
        result = self.run_analyzer(self.test_log_file.name, '--component-stats')
        self.assertEqual(result.returncode, 0)
        self.assertIn("[auth]", result.stdout)
        self.assertIn("[web]", result.stdout)
        self.assertIn("[db]", result.stdout)
    
    def test_03_time_based_statistics(self):
        """Test time-based statistics."""
        print("✓ Testing: Time-based statistics")
        result = self.run_analyzer(self.test_log_file.name, '--time-stats', 'minute')
        self.assertEqual(result.returncode, 0)
        self.assertIn("08:00", result.stdout)
        self.assertRegex(result.stdout, r'[0-9]+ entries')
    
    def test_04_response_time_analysis(self):
        """Test response time analysis for web logs."""
        print("✓ Testing: Response time analysis")
        result = self.run_analyzer(self.test_log_file.name, '--analyze-response-times')
        self.assertEqual(result.returncode, 0)
        # Should find the 1234ms and 5ms response times
        self.assertIn("ms", result.stdout)
        self.assertIn("average", result.stdout.lower())
    
    def test_05_top_errors(self):
        """Test finding most common error messages."""
        print("✓ Testing: Find top errors")
        result = self.run_analyzer(self.test_log_file.name, '--top-errors', '3')
        self.assertEqual(result.returncode, 0)
        self.assertIn("Failed login attempt", result.stdout)
        # Should show count
        self.assertRegex(result.stdout, r'[0-9]+ occurrences')


class TestPatternDetection(BaseTestCase):
    """Test pattern detection features."""
    
    def test_01_detect_failed_logins(self):
        """Test detection of multiple failed login attempts."""
        print("\n✓ Testing: Detect failed login attempts")
        result = self.run_analyzer(self.test_log_file.name, '--detect-security')
        self.assertEqual(result.returncode, 0)
        self.assertIn("192.168.1.100", result.stdout)
        self.assertIn("failed", result.stdout.lower())
        self.assertIn("5", result.stdout)  # Number of attempts
    
    def test_02_detect_slow_queries(self):
        """Test detection of slow queries."""
        print("✓ Testing: Detect slow queries")
        result = self.run_analyzer(
            self.test_log_file.name,
            '--detect-slow-queries',
            '--threshold', '2000'
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("2345ms", result.stdout)
        self.assertIn("SELECT * FROM orders", result.stdout)
    
    def test_03_detect_security_events(self):
        """Test detection of security events."""
        print("✓ Testing: Detect security events")
        result = self.run_analyzer(self.test_log_file.name, '--detect-security')
        self.assertEqual(result.returncode, 0)
        self.assertIn("SQL injection", result.stdout)
        self.assertIn("Brute force", result.stdout)
    
    def test_04_detect_system_health(self):
        """Test detection of system health issues."""
        print("✓ Testing: Detect system health issues")
        result = self.run_analyzer(self.test_log_file.name, '--detect-health')
        self.assertEqual(result.returncode, 0)
        self.assertIn("High memory", result.stdout)
        self.assertIn("CPU usage critical", result.stdout)


class TestOutput(BaseTestCase):
    """Test output and reporting features."""
    
    def test_01_json_format(self):
        """Test JSON output format."""
        print("\n✓ Testing: JSON output format")
        result = self.run_analyzer(self.test_log_file.name, '--format', 'json', '--limit', '5')
        self.assertEqual(result.returncode, 0)
        try:
            data = json.loads(result.stdout)
            self.assertIsInstance(data, (dict, list))
        except json.JSONDecodeError:
            self.fail("Output should be valid JSON")
    
    def test_02_csv_format(self):
        """Test CSV output format."""
        print("✓ Testing: CSV output format")
        result = self.run_analyzer(self.test_log_file.name, '--format', 'csv', '--limit', '5')
        self.assertEqual(result.returncode, 0)
        reader = csv.reader(StringIO(result.stdout))
        rows = list(reader)
        self.assertGreater(len(rows), 1, "CSV should have header and data")
    
    def test_03_plain_text_format(self):
        """Test plain text output (default)."""
        print("✓ Testing: Plain text output format")
        result = self.run_analyzer(self.test_log_file.name, '--limit', '5')
        self.assertEqual(result.returncode, 0)
        self.assertIn("2024-07-16", result.stdout)
        self.assertNotIn("{", result.stdout)  # Not JSON
    
    def test_04_summary_report(self):
        """Test summary report generation."""
        print("✓ Testing: Summary report generation")
        result = self.run_analyzer(self.test_log_file.name, '--summary')
        self.assertEqual(result.returncode, 0)
        self.assertIn("Total entries", result.stdout)
        self.assertIn("Error count", result.stdout)
        self.assertIn("Time range", result.stdout)
    
    def test_05_export_to_file(self):
        """Test exporting to file."""
        print("✓ Testing: Export to file")
        output_file = tempfile.NamedTemporaryFile(delete=False)
        output_file.close()
        
        result = self.run_analyzer(
            self.test_log_file.name,
            '--level', 'ERROR',
            '--output', output_file.name
        )
        self.assertEqual(result.returncode, 0)
        
        with open(output_file.name, 'r') as f:
            content = f.read()
            self.assertIn("ERROR", content)
        
        os.unlink(output_file.name)


class TestInterface(BaseTestCase):
    """Test CLI interface and usability."""
    
    def test_01_help_text(self):
        """Test help text display."""
        print("\n✓ Testing: Help text")
        result = self.run_analyzer('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage:", result.stdout.lower())
        self.assertIn("--level", result.stdout)
        self.assertIn("--format", result.stdout)
    
    def test_02_error_invalid_file(self):
        """Test error handling for invalid file."""
        print("✓ Testing: Error handling for invalid file")
        result = self.run_analyzer('nonexistent.log')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", result.stderr.lower())
    
    def test_03_error_invalid_arguments(self):
        """Test error handling for invalid arguments."""
        print("✓ Testing: Error handling for invalid arguments")
        result = self.run_analyzer(self.test_log_file.name, '--level', 'INVALID')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error", result.stderr.lower())
        self.assertIn("INVALID", result.stderr)
    
    def test_04_multiple_operations(self):
        """Test combining multiple operations."""
        print("✓ Testing: Multiple operations in one command")
        result = self.run_analyzer(
            self.test_log_file.name,
            '--stats',
            '--top-errors', '3',
            '--format', 'json'
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("statistics", str(data))


class TestExtensibility(BaseTestCase):
    """Test extensibility features."""
    
    def test_01_config_file_support(self):
        """Test configuration file support."""
        print("\n✓ Testing: Configuration file support")
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        config_file.write("""
# Configuration for log analyzer
level = ERROR
component = auth
format = json
""")
        config_file.close()
        
        result = self.run_analyzer(self.test_log_file.name, '--config', config_file.name)
        # Should apply config settings
        if result.returncode == 0:
            try:
                json.loads(result.stdout)
                self.assertTrue(True, "Config applied successfully")
            except:
                self.fail("Config should set JSON format")
        
        os.unlink(config_file.name)
    
    def test_02_extensible_architecture(self):
        """Test that architecture supports extensions."""
        print("✓ Testing: Extensible architecture")
        # Check if there's a way to list available filters/analyzers
        result = self.run_analyzer('--list-filters')
        # This is optional - implementations may handle this differently
        pass


def create_test_suite(test_section=None):
    """Create a test suite based on the requested section."""
    if test_section == 'all':
        return unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    
    section_mapping = {
        'parsing': TestParsing,
        'filtering': TestFiltering,
        'analytics': TestAnalytics,
        'patterns': TestPatternDetection,
        'output': TestOutput,
        'interface': TestInterface,
        'extensibility': TestExtensibility,
    }
    
    if test_section in section_mapping:
        suite = unittest.TestSuite()
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(section_mapping[test_section]))
        return suite
    else:
        print(f"Unknown section: {test_section}")
        print(f"Available sections: {', '.join(section_mapping.keys())}")
        return None


def main():
    parser = argparse.ArgumentParser(description='Test Log Analyzer Implementation')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('--parsing', action='store_true', help='Test parsing features')
    parser.add_argument('--filtering', action='store_true', help='Test filtering features')
    parser.add_argument('--analytics', action='store_true', help='Test analytics features')
    parser.add_argument('--patterns', action='store_true', help='Test pattern detection')
    parser.add_argument('--output', action='store_true', help='Test output features')
    parser.add_argument('--interface', action='store_true', help='Test CLI interface')
    parser.add_argument('--extensibility', action='store_true', help='Test extensibility')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Determine which section to test
    if args.all:
        section = 'all'
    elif args.parsing:
        section = 'parsing'
    elif args.filtering:
        section = 'filtering'
    elif args.analytics:
        section = 'analytics'
    elif args.patterns:
        section = 'patterns'
    elif args.output:
        section = 'output'
    elif args.interface:
        section = 'interface'
    elif args.extensibility:
        section = 'extensibility'
    else:
        print("Please specify a test section or --all")
        parser.print_help()
        return
    
    # Create and run the test suite
    suite = create_test_suite(section)
    if suite:
        print(f"\n{'='*60}")
        print(f"Running {section.upper()} tests for Log Analyzer")
        print(f"{'='*60}")
        
        verbosity = 2 if args.verbose else 1
        runner = unittest.TextTestRunner(verbosity=verbosity)
        result = runner.run(suite)
        
        # Print summary
        print(f"\n{'='*60}")
        if result.wasSuccessful():
            print(f"✅ All {section} tests passed!")
        else:
            print(f"❌ Some {section} tests failed")
            print(f"Failures: {len(result.failures)}")
            print(f"Errors: {len(result.errors)}")
        print(f"{'='*60}")


if __name__ == '__main__':
    main()