#!/usr/bin/env python3
"""
Basic Log Analyzer
A simple tool to parse and analyze log files
"""

import re
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from security_analyzer import SecurityAnalyzer


class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = Path(log_file)
        self.entries = []
        self.stats = defaultdict(int)
        self.security_analyzer = SecurityAnalyzer()
        
    def parse_log(self):
        """Parse the log file and extract entries"""
        if not self.log_file.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_file}")
            
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    entry = self._parse_line(line, line_num)
                    if entry:
                        self.entries.append(entry)
                        
    def _parse_line(self, line, line_num):
        """Parse a single log line"""
        # Common log patterns
        patterns = [
            # Apache/Nginx access log with user agent
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\].*?"(?P<method>\w+)\s+(?P<path>\S+).*?"\s+(?P<status>\d+)\s+(?P<size>\d+|-).*?"(?P<user_agent>[^"]*)"',
            # Apache/Nginx access log without user agent
            r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>[^\]]+)\].*?"(?P<method>\w+)\s+(?P<path>\S+).*?"\s+(?P<status>\d+)\s+(?P<size>\d+|-)',
            # Common application log with timestamp
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?P<level>DEBUG|INFO|WARN|ERROR|FATAL).*?(?P<message>.*)',
            # Syslog format
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                entry = match.groupdict()
                entry['line_num'] = line_num
                entry['raw_line'] = line
                return entry
                
        # If no pattern matches, create a basic entry
        return {
            'line_num': line_num,
            'raw_line': line,
            'message': line,
            'timestamp': None
        }
    
    def analyze(self):
        """Perform basic analysis on the log entries"""
        if not self.entries:
            print("No log entries found to analyze")
            return
            
        self.stats['total_entries'] = len(self.entries)
        
        # Count by log level
        levels = Counter()
        status_codes = Counter()
        ips = Counter()
        
        for entry in self.entries:
            if 'level' in entry:
                levels[entry['level']] += 1
            if 'status' in entry:
                status_codes[entry['status']] += 1
            if 'ip' in entry:
                ips[entry['ip']] += 1
                
        self.stats['levels'] = levels
        self.stats['status_codes'] = status_codes
        self.stats['top_ips'] = ips.most_common(10)
        
    def print_summary(self):
        """Print analysis summary"""
        print(f"\n=== Log Analysis Summary ===")
        print(f"File: {self.log_file}")
        print(f"Total entries: {self.stats['total_entries']}")
        
        if self.stats['levels']:
            print(f"\nLog Levels:")
            for level, count in self.stats['levels'].most_common():
                print(f"  {level}: {count}")
                
        if self.stats['status_codes']:
            print(f"\nHTTP Status Codes:")
            for code, count in self.stats['status_codes'].most_common():
                print(f"  {code}: {count}")
                
        if self.stats['top_ips']:
            print(f"\nTop IP Addresses:")
            for ip, count in self.stats['top_ips']:
                print(f"  {ip}: {count}")
    
    def search(self, pattern, case_sensitive=False):
        """Search for specific patterns in logs"""
        flags = 0 if case_sensitive else re.IGNORECASE
        matches = []
        
        for entry in self.entries:
            if re.search(pattern, entry['raw_line'], flags):
                matches.append(entry)
                
        return matches
    
    def filter_by_level(self, level):
        """Filter entries by log level"""
        return [entry for entry in self.entries if entry.get('level', '').upper() == level.upper()]
    
    def filter_by_timerange(self, start_time, end_time):
        """Filter entries by time range (basic implementation)"""
        # This is a simplified version - you might want to improve timestamp parsing
        filtered = []
        for entry in self.entries:
            if entry.get('timestamp'):
                # Add your timestamp parsing logic here
                filtered.append(entry)
        return filtered
    
    def security_analysis(self):
        """Perform comprehensive security analysis"""
        all_threats = []
        
        # Analyze each entry for security threats
        for entry in self.entries:
            threats = self.security_analyzer.analyze_entry(entry)
            all_threats.extend(threats)
            
        # Detect brute force attempts
        brute_force = self.security_analyzer.detect_brute_force()
        
        # Detect rate limiting violations
        rate_limiting = self.security_analyzer.detect_rate_limiting()
        
        # Establish baseline and detect anomalies
        baseline = self.security_analyzer.establish_baseline(self.entries)
        anomalies = self.security_analyzer.detect_anomalies(self.entries, baseline)
        
        # Generate comprehensive report
        report = self.security_analyzer.generate_security_report(
            all_threats, brute_force, rate_limiting, anomalies
        )
        
        return report, all_threats


def main():
    parser = argparse.ArgumentParser(description='Analyze log files')
    parser.add_argument('logfile', help='Path to log file')
    parser.add_argument('--search', help='Search for pattern in logs')
    parser.add_argument('--level', help='Filter by log level (DEBUG, INFO, WARN, ERROR)')
    parser.add_argument('--case-sensitive', action='store_true', help='Case sensitive search')
    parser.add_argument('--security', action='store_true', help='Perform security analysis')
    parser.add_argument('--threats-only', action='store_true', help='Show only security threats')
    
    args = parser.parse_args()
    
    try:
        analyzer = LogAnalyzer(args.logfile)
        analyzer.parse_log()
        analyzer.analyze()
        
        if not args.threats_only:
            analyzer.print_summary()
        
        if args.security or args.threats_only:
            report, threats = analyzer.security_analysis()
            analyzer.security_analyzer.print_security_report(report)
            
            if threats and args.threats_only:
                print(f"\n=== DETAILED THREAT ANALYSIS ===")
                for i, threat in enumerate(threats[:20], 1):
                    entry = threat['entry']
                    print(f"\n{i}. {threat['type'].upper()} ({threat['severity']} severity)")
                    print(f"   Line {entry['line_num']}: {entry['raw_line'][:100]}...")
                    if entry.get('ip'):
                        print(f"   IP: {entry['ip']}")
        
        if args.search:
            matches = analyzer.search(args.search, args.case_sensitive)
            print(f"\n=== Search Results for '{args.search}' ===")
            for match in matches[:20]:  # Limit to first 20 matches
                print(f"Line {match['line_num']}: {match['raw_line']}")
                
        if args.level:
            filtered = analyzer.filter_by_level(args.level)
            print(f"\n=== {args.level} Level Entries ===")
            for entry in filtered[:10]:  # Limit to first 10
                print(f"Line {entry['line_num']}: {entry['raw_line']}")
                
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()