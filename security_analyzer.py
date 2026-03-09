#!/usr/bin/env python3
"""
Security-focused log analysis module
Detects common attack patterns and suspicious behavior
"""

import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta


class SecurityAnalyzer:
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': [
                r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from)",
                r"(?i)(\'\s*or\s+\d+\s*=\s*\d+|admin\'\s*--|\'\s*or\s+\'1\'\s*=\s*\'1)",
                r"(?i)(drop\s+table|truncate\s+table|alter\s+table)"
            ],
            'xss_attempts': [
                r"(?i)(<script|javascript:|onload=|onerror=|onclick=)",
                r"(?i)(alert\(|document\.cookie|window\.location)",
                r"(?i)(<iframe|<object|<embed)"
            ],
            'path_traversal': [
                r"(\.\./){2,}",
                r"(?i)(etc/passwd|windows/system32|boot\.ini)",
                r"(?i)(\.\.\\|\.\.%2f|\.\.%5c)"
            ],
            'command_injection': [
                r"(?i)(;|\||\&)\s*(cat|ls|dir|type|ping|wget|curl)",
                r"(?i)(\$\(|\`|system\(|exec\(|shell_exec)",
                r"(?i)(nc\s+-|netcat|/bin/sh|cmd\.exe)"
            ],
            'brute_force': [
                r"(?i)(admin|administrator|root|test|guest)",
                r"(?i)(password|passwd|login|auth)"
            ]
        }
        
        self.suspicious_user_agents = [
            r"(?i)(sqlmap|nikto|nmap|masscan|zap|burp)",
            r"(?i)(python-requests|curl|wget|libwww)",
            r"(?i)(bot|crawler|spider|scraper)"
        ]
        
        self.security_events = defaultdict(list)
        self.failed_logins = defaultdict(list)
        self.rate_limits = defaultdict(list)
        
    def analyze_entry(self, entry):
        """
        Analyze a single log entry for security issues
        
        Args:
            entry: Dict containing parsed log entry data
            
        Returns:
            List of threat dicts with type, pattern, severity, and entry
        """
        if not entry:
            return []
            
        threats = []
        
        # Check for attack patterns
        content = entry.get('raw_line', '')
        path = entry.get('path', '')
        user_agent = entry.get('user_agent', '')
        
        # Detect attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, content):
                        threats.append({
                            'type': attack_type,
                            'pattern': pattern,
                            'severity': self._get_severity(attack_type),
                            'entry': entry
                        })
                except re.error:
                    # Skip invalid regex patterns
                    continue
                    
        # Check suspicious user agents
        for pattern in self.suspicious_user_agents:
            try:
                if re.search(pattern, user_agent):
                    threats.append({
                        'type': 'suspicious_user_agent',
                        'pattern': pattern,
                        'severity': 'medium',
                        'entry': entry
                    })
            except re.error:
                continue
                
        # Track failed logins (4xx status codes)
        status = entry.get('status')
        if status in ['401', '403', '404']:
            ip = entry.get('ip')
            if ip:
                self.failed_logins[ip].append(entry)
                
        # Track request rates per IP
        ip = entry.get('ip')
        if ip:
            self.rate_limits[ip].append(entry)
            
        return threats
    
    def _get_severity(self, attack_type):
        """
        Determine severity level for attack type
        
        Args:
            attack_type: String identifying the type of attack
            
        Returns:
            String severity level: 'critical', 'high', 'medium', or 'low'
        """
        severity_map = {
            'sql_injection': 'high',
            'xss_attempts': 'high',
            'path_traversal': 'high',
            'command_injection': 'critical',
            'brute_force': 'medium'
        }
        return severity_map.get(attack_type, 'low')
    
    def detect_brute_force(self, threshold=10, time_window=300):
        """
        Detect potential brute force attacks
        
        Args:
            threshold: Minimum number of failed attempts to trigger alert
            time_window: Time window in seconds (reserved for future enhancement)
        
        Returns:
            List of dicts containing IP addresses with suspicious failed login patterns
        """
        brute_force_ips = []
        
        for ip, attempts in self.failed_logins.items():
            if len(attempts) >= threshold:
                # Check if attempts are within time window
                if len(attempts) > 1:
                    # Simple time window check (would need proper timestamp parsing)
                    brute_force_ips.append({
                        'ip': ip,
                        'attempts': len(attempts),
                        'severity': 'high' if len(attempts) > 20 else 'medium'
                    })
                    
        return brute_force_ips
    
    def detect_rate_limiting(self, threshold=100, time_window=60):
        """
        Detect potential DDoS or excessive requests
        
        Args:
            threshold: Minimum number of requests to trigger alert
            time_window: Time window in seconds (reserved for future enhancement)
        
        Returns:
            List of dicts containing IP addresses with excessive request patterns
        """
        suspicious_ips = []
        
        for ip, requests in self.rate_limits.items():
            if len(requests) >= threshold:
                suspicious_ips.append({
                    'ip': ip,
                    'requests': len(requests),
                    'severity': 'high' if len(requests) > 500 else 'medium'
                })
                
        return suspicious_ips
    
    def establish_baseline(self, entries):
        """
        Establish baseline behavior patterns from log entries
        
        Args:
            entries: List of parsed log entry dictionaries
        
        Returns:
            Dict containing baseline metrics for normal behavior
        """
        if not entries:
            return {
                'avg_requests_per_ip': 0,
                'common_paths': Counter(),
                'common_user_agents': Counter(),
                'status_code_distribution': Counter(),
                'peak_hours': Counter()
            }
            
        baseline = {
            'avg_requests_per_ip': 0,
            'common_paths': Counter(),
            'common_user_agents': Counter(),
            'status_code_distribution': Counter(),
            'peak_hours': Counter()
        }
        
        ip_requests = Counter()
        
        for entry in entries:
            ip = entry.get('ip')
            if ip:
                ip_requests[ip] += 1
                
            path = entry.get('path')
            if path:
                baseline['common_paths'][path] += 1
                
            user_agent = entry.get('user_agent', '')
            if user_agent:
                baseline['common_user_agents'][user_agent] += 1
                
            status = entry.get('status')
            if status:
                baseline['status_code_distribution'][status] += 1
                
        if ip_requests:
            baseline['avg_requests_per_ip'] = sum(ip_requests.values()) / len(ip_requests)
        else:
            baseline['avg_requests_per_ip'] = 0
            
        return baseline
    
    def detect_anomalies(self, entries, baseline):
        """
        Detect anomalous behavior based on established baseline
        
        Args:
            entries: List of parsed log entry dictionaries
            baseline: Dict containing baseline metrics from establish_baseline()
        
        Returns:
            List of detected anomalies with details
        """
        if not entries or not baseline:
            return []
            
        anomalies = []
        
        ip_requests = Counter()
        for entry in entries:
            ip = entry.get('ip')
            if ip:
                ip_requests[ip] += 1
                
        # Detect IPs with unusually high request counts
        avg_requests = baseline.get('avg_requests_per_ip', 0)
        if avg_requests > 0:
            threshold = avg_requests * 5  # 5x normal activity
            
            for ip, count in ip_requests.items():
                if count > threshold:
                    anomalies.append({
                        'type': 'unusual_activity',
                        'ip': ip,
                        'requests': count,
                        'baseline_avg': avg_requests,
                        'severity': 'medium'
                    })
                
        return anomalies
    
    def generate_security_report(self, threats, brute_force, rate_limiting, anomalies):
        """
        Generate a comprehensive security report
        
        Args:
            threats: List of detected security threats
            brute_force: List of brute force attack attempts
            rate_limiting: List of rate limiting violations
            anomalies: List of detected anomalies
        
        Returns:
            Dict containing comprehensive security analysis report
        """
        # Ensure all inputs are lists
        threats = threats or []
        brute_force = brute_force or []
        rate_limiting = rate_limiting or []
        anomalies = anomalies or []
        
        # Filter out None IPs before counting
        valid_threat_ips = [t.get('entry', {}).get('ip') for t in threats 
                           if t.get('entry', {}).get('ip') is not None]
        
        report = {
            'summary': {
                'total_threats': len(threats),
                'critical_threats': len([t for t in threats if t.get('severity') == 'critical']),
                'high_threats': len([t for t in threats if t.get('severity') == 'high']),
                'brute_force_attempts': len(brute_force),
                'rate_limit_violations': len(rate_limiting),
                'anomalies': len(anomalies)
            },
            'threats_by_type': Counter([t.get('type', 'unknown') for t in threats]),
            'top_attacking_ips': Counter(valid_threat_ips).most_common(10),
            'brute_force_ips': brute_force,
            'rate_limiting_ips': rate_limiting,
            'anomalies': anomalies
        }
        
        return report
    
    def print_security_report(self, report):
        """
        Print formatted security report to console
        
        Args:
            report: Dict containing security analysis report from generate_security_report()
        """
        if not report:
            print("\n=== SECURITY ANALYSIS REPORT ===")
            print("No data available for security report")
            return
            
        print(f"\n=== SECURITY ANALYSIS REPORT ===")
        
        summary = report.get('summary', {})
        print(f"\nThreat Summary:")
        print(f"  Total threats detected: {summary.get('total_threats', 0)}")
        print(f"  Critical: {summary.get('critical_threats', 0)}")
        print(f"  High: {summary.get('high_threats', 0)}")
        print(f"  Brute force attempts: {summary.get('brute_force_attempts', 0)}")
        print(f"  Rate limit violations: {summary.get('rate_limit_violations', 0)}")
        print(f"  Anomalies: {summary.get('anomalies', 0)}")
        
        threats_by_type = report.get('threats_by_type', {})
        if threats_by_type:
            print(f"\nThreats by Type:")
            for threat_type, count in threats_by_type.most_common():
                print(f"  {threat_type.replace('_', ' ').title()}: {count}")
                
        top_attacking_ips = report.get('top_attacking_ips', [])
        if top_attacking_ips:
            print(f"\nTop Attacking IPs:")
            for ip, count in top_attacking_ips:
                if ip:  # Only print non-None IPs
                    print(f"  {ip}: {count} threats")
                
        brute_force_ips = report.get('brute_force_ips', [])
        if brute_force_ips:
            print(f"\nBrute Force Attempts:")
            for bf in brute_force_ips[:5]:
                print(f"  {bf.get('ip', 'unknown')}: {bf.get('attempts', 0)} failed attempts ({bf.get('severity', 'unknown')} severity)")
                
        rate_limiting_ips = report.get('rate_limiting_ips', [])
        if rate_limiting_ips:
            print(f"\nExcessive Request Activity:")
            for rl in rate_limiting_ips[:5]:
                print(f"  {rl.get('ip', 'unknown')}: {rl.get('requests', 0)} requests ({rl.get('severity', 'unknown')} severity)")
                
        anomalies_list = report.get('anomalies', [])
        if anomalies_list:
            print(f"\nAnomalous Behavior:")
            for anomaly in anomalies_list[:5]:
                baseline_avg = anomaly.get('baseline_avg', 0)
                print(f"  {anomaly.get('ip', 'unknown')}: {anomaly.get('requests', 0)} requests (avg: {baseline_avg:.1f})")
