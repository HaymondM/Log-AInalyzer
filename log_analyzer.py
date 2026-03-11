#!/usr/bin/env python3
"""
Basic Log Analyzer
A simple tool to parse and analyze log files
"""

import re
import argparse
import traceback
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from security_analyzer import SecurityAnalyzer
from core_analyzer import CoreAnalyzer


class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = Path(log_file)
        self.entries = []
        self.stats = defaultdict(int)
        self.security_analyzer = SecurityAnalyzer()
        self.core_analyzer = CoreAnalyzer()
        
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
    
    def core_analysis(self):
        """Perform comprehensive core analysis"""
        analysis_results = {}
        
        try:
            # Time-based analysis
            analysis_results['time_patterns'] = self.core_analyzer.analyze_time_patterns(self.entries)
            
            # User agent analysis
            analysis_results['user_agents'] = self.core_analyzer.analyze_user_agents(self.entries)
            
            # Performance analysis
            analysis_results['performance'] = self.core_analyzer.analyze_response_times(self.entries)
            
            # Geographic analysis
            analysis_results['geographic'] = self.core_analyzer.analyze_geographic_patterns(self.entries)
            
            # File access patterns
            analysis_results['file_access'] = self.core_analyzer.analyze_file_access_patterns(self.entries)
            
            # Session tracking
            analysis_results['sessions'] = self.core_analyzer.track_user_sessions(self.entries)
            
        except Exception as e:
            print(f"Error in core analysis: {e}")
            traceback.print_exc()
            
        return analysis_results
    
    def print_core_analysis(self, analysis_results):
        """Print formatted core analysis results"""
        print(f"\n=== CORE ANALYSIS REPORT ===")
        
        # Time patterns
        time_data = analysis_results.get('time_patterns', {})
        if time_data:
            print(f"\nTime Patterns:")
            if time_data.get('peak_hour'):
                print(f"  Peak hour: {time_data['peak_hour'][0]}:00 ({time_data['peak_hour'][1]} requests)")
            if time_data.get('peak_day'):
                print(f"  Peak day: {time_data['peak_day'][0]} ({time_data['peak_day'][1]} requests)")
            
            hourly = time_data.get('hourly_distribution', {})
            if hourly:
                print(f"  Hourly distribution (top 5):")
                for hour, count in sorted(hourly.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"    {hour}:00 - {count} requests")
        
        # User agents
        ua_data = analysis_results.get('user_agents', {})
        if ua_data:
            print(f"\nUser Agent Analysis:")
            print(f"  Total unique user agents: {ua_data.get('total_unique_agents', 0)}")
            
            browsers = ua_data.get('browsers', {})
            if browsers:
                print(f"  Top browsers:")
                for browser, count in sorted(browsers.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"    {browser}: {count}")
            
            os_systems = ua_data.get('operating_systems', {})
            if os_systems:
                print(f"  Top operating systems:")
                for os_name, count in sorted(os_systems.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"    {os_name}: {count}")
        
        # Performance
        perf_data = analysis_results.get('performance')
        if perf_data:
            print(f"\nPerformance Metrics:")
            print(f"  Average response time: {perf_data.get('average_response_time', 0)} ms")
            print(f"  95th percentile: {perf_data.get('p95_response_time', 0)} ms")
            print(f"  99th percentile: {perf_data.get('p99_response_time', 0)} ms")
            print(f"  Slow requests (>1s): {perf_data.get('slow_requests', 0)}")
            
            slowest_paths = perf_data.get('slowest_paths', [])
            if slowest_paths:
                print(f"  Slowest paths:")
                for path, avg_time in slowest_paths[:5]:
                    print(f"    {path}: {avg_time} ms")
        
        # Geographic
        geo_data = analysis_results.get('geographic', {})
        if geo_data:
            print(f"\nGeographic Analysis:")
            print(f"  Unique IP addresses: {geo_data.get('unique_ips', 0)}")
            
            regions = geo_data.get('estimated_regions', {})
            if regions:
                print(f"  Estimated regions:")
                for region, count in regions.items():
                    print(f"    {region}: {count} IPs")
            
            req_per_ip = geo_data.get('requests_per_ip', {})
            if req_per_ip:
                print(f"  Requests per IP - Avg: {req_per_ip.get('average', 0):.1f}, Max: {req_per_ip.get('max', 0)}")
        
        # File access
        file_data = analysis_results.get('file_access', {})
        if file_data:
            print(f"\nFile Access Patterns:")
            
            static_dynamic = file_data.get('static_vs_dynamic', {})
            if static_dynamic:
                print(f"  Static content: {static_dynamic.get('static_percentage', 0)}%")
                print(f"  Dynamic content: {static_dynamic.get('dynamic_percentage', 0)}%")
            
            methods = file_data.get('http_methods', {})
            if methods:
                print(f"  HTTP methods:")
                for method, count in methods.items():
                    print(f"    {method}: {count}")
            
            file_types = file_data.get('file_types', {})
            if file_types:
                print(f"  Top file types:")
                for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"    .{ext}: {count}")
        
        # Sessions
        sessions = analysis_results.get('sessions', {})
        if sessions:
            print(f"\nSession Analysis:")
            print(f"  Active sessions: {len(sessions)}")
            
            if sessions:
                avg_duration = sum(s['duration_seconds'] for s in sessions.values()) / len(sessions)
                avg_requests = sum(s['request_count'] for s in sessions.values()) / len(sessions)
                print(f"  Average session duration: {avg_duration:.1f} seconds")
                print(f"  Average requests per session: {avg_requests:.1f}")
                
                # Top sessions by duration
                top_sessions = sorted(sessions.items(), key=lambda x: x[1]['duration_seconds'], reverse=True)[:5]
                print(f"  Longest sessions:")
                for ip, session_data in top_sessions:
                    print(f"    {ip}: {session_data['duration_seconds']:.1f}s, {session_data['request_count']} requests")


def main():
    parser = argparse.ArgumentParser(description='Analyze log files')
    parser.add_argument('logfile', help='Path to log file')
    parser.add_argument('--search', help='Search for pattern in logs')
    parser.add_argument('--level', help='Filter by log level (DEBUG, INFO, WARN, ERROR)')
    parser.add_argument('--case-sensitive', action='store_true', help='Case sensitive search')
    parser.add_argument('--security', action='store_true', help='Perform security analysis')
    parser.add_argument('--threats-only', action='store_true', help='Show only security threats')
    parser.add_argument('--core-analysis', action='store_true', help='Perform comprehensive core analysis')
    parser.add_argument('--export-csv', help='Export analysis to CSV file')
    parser.add_argument('--export-json', help='Export analysis to JSON file')
    parser.add_argument('--time-analysis', action='store_true', help='Show detailed time-based analysis')
    parser.add_argument('--user-agents', action='store_true', help='Show detailed user agent analysis')
    parser.add_argument('--performance', action='store_true', help='Show performance metrics')
    
    args = parser.parse_args()
    
    try:
        analyzer = LogAnalyzer(args.logfile)
        analyzer.parse_log()
        analyzer.analyze()
        
        if not args.threats_only:
            analyzer.print_summary()
        
        # Core analysis
        if args.core_analysis or args.time_analysis or args.user_agents or args.performance:
            analysis_results = analyzer.core_analysis()
            analyzer.print_core_analysis(analysis_results)
            
            # Export if requested
            if args.export_csv:
                analyzer.core_analyzer.export_analysis_to_csv(analysis_results, args.export_csv)
                print(f"\nAnalysis exported to {args.export_csv}")
                
            if args.export_json:
                analyzer.core_analyzer.export_analysis_to_json(analysis_results, args.export_json)
                print(f"\nAnalysis exported to {args.export_json}")
        
        # Security analysis
        if args.security or args.threats_only:
            report, threats = analyzer.security_analysis()
            analyzer.security_analyzer.print_security_report(report)
            
            if threats and args.threats_only:
                print(f"\n=== DETAILED THREAT ANALYSIS ===")
                for threat in threats[:20]:  # Show top 20 threats
                    print(f"\nThreat Type: {threat['type']}")
                    print(f"Severity: {threat['severity']}")
                    print(f"Line: {threat['entry'].get('raw_line', 'N/A')}")
        
        if args.search:
            results = analyzer.search(args.search, args.case_sensitive)
            print(f"\n=== Search Results ===")
            print(f"Found {len(results)} matches for pattern: {args.search}")
            for result in results[:10]:  # Show first 10 matches
                print(f"Line {result['line_num']}: {result['raw_line']}")
                
        if args.level:
            results = analyzer.filter_by_level(args.level)
            print(f"\n=== Filter Results ===")
            print(f"Found {len(results)} entries with level: {args.level}")
            for result in results[:10]:
                print(f"Line {result['line_num']}: {result['raw_line']}")
                
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
