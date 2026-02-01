#!/usr/bin/env python3
"""
Generate sample log files for testing the log analyzer
"""

import random
from datetime import datetime, timedelta


def generate_sample_logs():
    """Generate sample log files for testing"""
    
    # Sample web server access log with security threats
    with open('sample_access.log', 'w') as f:
        ips = ['192.168.1.100', '10.0.0.50', '203.0.113.45', '198.51.100.23', '185.220.101.42']
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        normal_paths = ['/api/users', '/login', '/dashboard', '/api/data', '/static/css/style.css']
        malicious_paths = [
            '/admin\' OR 1=1--',
            '/login?user=admin&pass=\' OR \'1\'=\'1',
            '/search?q=<script>alert(1)</script>',
            '/file?path=../../../etc/passwd',
            '/api/exec?cmd=cat /etc/passwd',
            '/login?user=admin&pass=admin123'
        ]
        status_codes = [200, 201, 404, 500, 403, 301, 401]
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'sqlmap/1.6.12',
            'Nikto/2.1.6',
            'python-requests/2.28.1',
            'curl/7.68.0'
        ]
        
        base_time = datetime.now() - timedelta(hours=24)
        
        # Generate normal traffic
        for i in range(80):
            timestamp = base_time + timedelta(minutes=i*5)
            ip = random.choice(ips[:3])  # Normal IPs
            method = random.choice(methods)
            path = random.choice(normal_paths)
            status = random.choice([200, 201, 404])
            size = random.randint(100, 5000)
            user_agent = user_agents[0]  # Normal browser
            
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
            f.write(log_line)
        
        # Generate malicious traffic
        for i in range(20):
            timestamp = base_time + timedelta(minutes=i*10)
            ip = random.choice(ips[3:])  # Suspicious IPs
            method = random.choice(['GET', 'POST'])
            path = random.choice(malicious_paths)
            status = random.choice([403, 404, 500])
            size = random.randint(100, 1000)
            user_agent = random.choice(user_agents[1:])  # Suspicious user agents
            
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
            f.write(log_line)
            
        # Generate brute force attempts
        brute_force_ip = '185.220.101.42'
        for i in range(15):
            timestamp = base_time + timedelta(minutes=i*2)
            log_line = f'{brute_force_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 401 256 "-" "curl/7.68.0"\n'
            f.write(log_line)
    
    # Sample application log with security events
    with open('sample_app.log', 'w') as f:
        levels = ['DEBUG', 'INFO', 'WARN', 'ERROR']
        normal_messages = [
            'User authentication successful',
            'Database connection established',
            'Cache miss for key: user_123',
            'Memory usage: 85%',
            'Processing request for user ID: 456',
            'Backup completed successfully'
        ]
        security_messages = [
            'Failed login attempt for user: admin',
            'SQL injection attempt detected in parameter: id',
            'XSS attempt blocked: <script>alert(1)</script>',
            'Path traversal attempt: ../../../etc/passwd',
            'Multiple failed authentication attempts from IP: 185.220.101.42',
            'Suspicious user agent detected: sqlmap/1.6.12'
        ]
        
        base_time = datetime.now() - timedelta(hours=12)
        
        # Normal log entries
        for i in range(40):
            timestamp = base_time + timedelta(minutes=i*10)
            level = random.choice(['DEBUG', 'INFO'])
            message = random.choice(normal_messages)
            
            log_line = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} [{level}] {message}\n'
            f.write(log_line)
            
        # Security-related entries
        for i in range(10):
            timestamp = base_time + timedelta(minutes=i*15)
            level = random.choice(['WARN', 'ERROR'])
            message = random.choice(security_messages)
            
            log_line = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} [{level}] {message}\n'
            f.write(log_line)
    
    print("Sample log files created:")
    print("- sample_access.log (web server access log with security threats)")
    print("- sample_app.log (application log with security events)")


if __name__ == "__main__":
    generate_sample_logs()