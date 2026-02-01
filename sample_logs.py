#!/usr/bin/env python3
"""
Generate sample log files for testing the log analyzer
"""

import random
from datetime import datetime, timedelta


def generate_sample_logs():
    """Generate sample log files for testing"""
    
    # Sample web server access log
    with open('sample_access.log', 'w') as f:
        ips = ['192.168.1.100', '10.0.0.50', '203.0.113.45', '198.51.100.23']
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        paths = ['/api/users', '/login', '/dashboard', '/api/data', '/static/css/style.css']
        status_codes = [200, 201, 404, 500, 403, 301]
        
        base_time = datetime.now() - timedelta(hours=24)
        
        for i in range(100):
            timestamp = base_time + timedelta(minutes=i*5)
            ip = random.choice(ips)
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choice(status_codes)
            size = random.randint(100, 5000)
            
            log_line = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size}\n'
            f.write(log_line)
    
    # Sample application log
    with open('sample_app.log', 'w') as f:
        levels = ['DEBUG', 'INFO', 'WARN', 'ERROR']
        messages = [
            'User authentication successful',
            'Database connection established',
            'Cache miss for key: user_123',
            'Failed to connect to external API',
            'Memory usage: 85%',
            'Processing request for user ID: 456',
            'Invalid input received',
            'Backup completed successfully'
        ]
        
        base_time = datetime.now() - timedelta(hours=12)
        
        for i in range(50):
            timestamp = base_time + timedelta(minutes=i*10)
            level = random.choice(levels)
            message = random.choice(messages)
            
            log_line = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} [{level}] {message}\n'
            f.write(log_line)
    
    print("Sample log files created:")
    print("- sample_access.log (web server access log)")
    print("- sample_app.log (application log)")


if __name__ == "__main__":
    generate_sample_logs()