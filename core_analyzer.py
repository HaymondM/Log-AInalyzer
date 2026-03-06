#!/usr/bin/env python3
"""
Core analysis features for log analyzer
Time-based analysis, geographic analysis, performance tracking, etc.
"""

import re
import json
import csv
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path


class CoreAnalyzer:
    def __init__(self):
        self.time_patterns = defaultdict(int)
        self.hourly_stats = defaultdict(int)
        self.daily_stats = defaultdict(int)
        self.response_times = []
        self.user_agents = Counter()
        self.referrers = Counter()
        self.file_extensions = Counter()
        self.session_tracking = defaultdict(list)
        
    def analyze_time_patterns(self, entries):
        """Analyze time-based patterns in log entries"""
        for entry in entries:
            timestamp_str = entry.get('timestamp')
            if timestamp_str:
                try:
                    # Try different timestamp formats
                    timestamp = self._parse_timestamp(timestamp_str)
                    if timestamp:
                        hour = timestamp.hour
                        day = timestamp.strftime('%Y-%m-%d')
                        day_of_week = timestamp.strftime('%A')
                        
                        self.hourly_stats[hour] += 1
                        self.daily_stats[day] += 1
                        self.time_patterns[day_of_week] += 1
                        
                except Exception:
                    continue
                    
        return {
            'hourly_distribution': dict(self.hourly_stats),
            'daily_distribution': dict(self.daily_stats),
            'day_of_week_distribution': dict(self.time_patterns),
            'peak_hour': max(self.hourly_stats.items(), key=lambda x: x[1]) if self.hourly_stats else None,
            'peak_day': max(self.daily_stats.items(), key=lambda x: x[1]) if self.daily_stats else None
        }
    
    def _parse_timestamp(self, timestamp_str):
        """Parse various timestamp formats"""
        formats = [
            '%d/%b/%Y:%H:%M:%S %z',  # Apache format
            '%Y-%m-%d %H:%M:%S',     # Application log format
            '%b %d %H:%M:%S',        # Syslog format
            '%Y-%m-%dT%H:%M:%S',     # ISO format
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        return None
    
    def analyze_user_agents(self, entries):
        """Analyze user agent patterns"""
        browsers = Counter()
        os_systems = Counter()
        devices = Counter()
        
        for entry in entries:
            user_agent = entry.get('user_agent', '')
            if user_agent:
                self.user_agents[user_agent] += 1
                
                # Extract browser info
                browser = self._extract_browser(user_agent)
                if browser:
                    browsers[browser] += 1
                    
                # Extract OS info
                os_info = self._extract_os(user_agent)
                if os_info:
                    os_systems[os_info] += 1
                    
                # Extract device info
                device = self._extract_device(user_agent)
                if device:
                    devices[device] += 1
        
        return {
            'top_user_agents': self.user_agents.most_common(10),
            'browsers': dict(browsers),
            'operating_systems': dict(os_systems),
            'devices': dict(devices),
            'total_unique_agents': len(self.user_agents)
        }
    
    def _extract_browser(self, user_agent):
        """Extract browser from user agent string"""
        browsers = {
            'Chrome': r'Chrome/[\d.]+',
            'Firefox': r'Firefox/[\d.]+',
            'Safari': r'Safari/[\d.]+',
            'Edge': r'Edg/[\d.]+',
            'Opera': r'Opera/[\d.]+',
            'Internet Explorer': r'MSIE [\d.]+',
            'Bot/Crawler': r'(bot|crawler|spider|scraper)',
            'Tool': r'(curl|wget|python|java|go-http)'
        }
        
        for browser, pattern in browsers.items():
            if re.search(pattern, user_agent, re.IGNORECASE):
                return browser
        return 'Unknown'
    
    def _extract_os(self, user_agent):
        """Extract operating system from user agent string"""
        os_patterns = {
            'Windows': r'Windows NT [\d.]+',
            'macOS': r'Mac OS X [\d._]+',
            'Linux': r'Linux',
            'Android': r'Android [\d.]+',
            'iOS': r'iPhone OS [\d._]+|iPad.*OS [\d._]+',
            'Unix': r'Unix'
        }
        
        for os_name, pattern in os_patterns.items():
            if re.search(pattern, user_agent, re.IGNORECASE):
                return os_name
        return 'Unknown'
    
    def _extract_device(self, user_agent):
        """Extract device type from user agent string"""
        if re.search(r'Mobile|Android|iPhone', user_agent, re.IGNORECASE):
            return 'Mobile'
        elif re.search(r'iPad|Tablet', user_agent, re.IGNORECASE):
            return 'Tablet'
        elif re.search(r'bot|crawler|spider', user_agent, re.IGNORECASE):
            return 'Bot'
        else:
            return 'Desktop'
    
    def analyze_response_times(self, entries):
        """Analyze response times and performance metrics"""
        response_times = []
        status_performance = defaultdict(list)
        path_performance = defaultdict(list)
        
        for entry in entries:
            # Extract response time if available (would need to be in log format)
            # For now, simulate based on response size and status
            size = entry.get('size')
            status = entry.get('status')
            path = entry.get('path')
            
            if size and size != '-':
                try:
                    size_int = int(size)
                    # Simulate response time based on size (rough approximation)
                    response_time = max(10, size_int / 1000)  # ms
                    response_times.append(response_time)
                    
                    if status:
                        status_performance[status].append(response_time)
                    if path:
                        path_performance[path].append(response_time)
                        
                except ValueError:
                    continue
        
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            max_response_time = max(response_times)
            min_response_time = min(response_times)
            
            # Calculate percentiles
            sorted_times = sorted(response_times)
            p95 = sorted_times[int(len(sorted_times) * 0.95)] if sorted_times else 0
            p99 = sorted_times[int(len(sorted_times) * 0.99)] if sorted_times else 0
            
            return {
                'average_response_time': round(avg_response_time, 2),
                'max_response_time': round(max_response_time, 2),
                'min_response_time': round(min_response_time, 2),
                'p95_response_time': round(p95, 2),
                'p99_response_time': round(p99, 2),
                'slow_requests': len([t for t in response_times if t > 1000]),  # > 1 second
                'status_performance': {k: round(sum(v)/len(v), 2) for k, v in status_performance.items()},
                'slowest_paths': sorted([(k, round(sum(v)/len(v), 2)) for k, v in path_performance.items()], 
                                      key=lambda x: x[1], reverse=True)[:10]
            }
        
        return None
    
    def analyze_geographic_patterns(self, entries):
        """Analyze geographic patterns from IP addresses"""
        # This is a simplified version - in production you'd use a GeoIP database
        ip_patterns = Counter()
        ip_ranges = defaultdict(int)
        
        for entry in entries:
            ip = entry.get('ip')
            if ip:
                ip_patterns[ip] += 1
                
                # Simple IP range analysis
                ip_parts = ip.split('.')
                if len(ip_parts) == 4:
                    # Class A network
                    class_a = ip_parts[0]
                    ip_ranges[f"{class_a}.x.x.x"] += 1
        
        # Identify potential geographic regions based on IP ranges
        regions = self._classify_ip_regions(ip_patterns.keys())
        
        return {
            'unique_ips': len(ip_patterns),
            'top_ips': ip_patterns.most_common(20),
            'ip_ranges': dict(ip_ranges),
            'estimated_regions': regions,
            'requests_per_ip': {
                'average': sum(ip_patterns.values()) / len(ip_patterns) if ip_patterns else 0,
                'max': max(ip_patterns.values()) if ip_patterns else 0,
                'min': min(ip_patterns.values()) if ip_patterns else 0
            }
        }
    
    def _classify_ip_regions(self, ips):
        """Simple IP region classification (would use GeoIP in production)"""
        regions = Counter()
        
        for ip in ips:
            try:
                first_octet = int(ip.split('.')[0])
                
                # Very basic classification
                if first_octet == 192 or first_octet == 10 or first_octet == 172:
                    regions['Private/Local'] += 1
                elif 1 <= first_octet <= 126:
                    regions['North America/Europe'] += 1
                elif 128 <= first_octet <= 191:
                    regions['Global/Mixed'] += 1
                elif 193 <= first_octet <= 223:
                    regions['Asia/Pacific'] += 1
                else:
                    regions['Unknown/Reserved'] += 1
            except (ValueError, IndexError):
                regions['Invalid'] += 1
                
        return dict(regions)
    
    def analyze_file_access_patterns(self, entries):
        """Analyze file access patterns and resource usage"""
        file_types = Counter()
        path_popularity = Counter()
        method_usage = Counter()
        
        for entry in entries:
            path = entry.get('path', '')
            method = entry.get('method', '')
            
            if path:
                path_popularity[path] += 1
                
                # Extract file extension
                if '.' in path:
                    extension = path.split('.')[-1].lower()
                    # Filter out query parameters
                    extension = extension.split('?')[0]
                    if extension and len(extension) <= 5:  # Reasonable extension length
                        file_types[extension] += 1
                        
            if method:
                method_usage[method] += 1
        
        return {
            'file_types': dict(file_types),
            'most_popular_paths': path_popularity.most_common(20),
            'http_methods': dict(method_usage),
            'static_vs_dynamic': self._classify_static_dynamic(path_popularity),
            'api_endpoints': self._identify_api_endpoints(path_popularity)
        }
    
    def _classify_static_dynamic(self, path_popularity):
        """Classify requests as static or dynamic content"""
        static_extensions = {'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'ttf'}
        static_count = 0
        dynamic_count = 0
        
        for path, count in path_popularity.items():
            if any(path.endswith(f'.{ext}') for ext in static_extensions):
                static_count += count
            else:
                dynamic_count += count
                
        total = static_count + dynamic_count
        return {
            'static_requests': static_count,
            'dynamic_requests': dynamic_count,
            'static_percentage': round((static_count / total * 100), 2) if total > 0 else 0,
            'dynamic_percentage': round((dynamic_count / total * 100), 2) if total > 0 else 0
        }
    
    def _identify_api_endpoints(self, path_popularity):
        """Identify API endpoints from paths"""
        api_paths = []
        
        for path, count in path_popularity.items():
            if any(indicator in path.lower() for indicator in ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']):
                api_paths.append((path, count))
                
        return sorted(api_paths, key=lambda x: x[1], reverse=True)[:10]
    
    def track_user_sessions(self, entries):
        """Basic session tracking based on IP addresses"""
        sessions = defaultdict(lambda: {'requests': [], 'duration': 0, 'pages': set()})
        
        for entry in entries:
            ip = entry.get('ip')
            timestamp_str = entry.get('timestamp')
            path = entry.get('path')
            
            if ip and timestamp_str:
                timestamp = self._parse_timestamp(timestamp_str)
                if timestamp:
                    sessions[ip]['requests'].append(timestamp)
                    if path:
                        sessions[ip]['pages'].add(path)
        
        # Calculate session durations
        session_stats = {}
        for ip, session_data in sessions.items():
            if len(session_data['requests']) > 1:
                requests = sorted(session_data['requests'])
                duration = (requests[-1] - requests[0]).total_seconds()
                session_stats[ip] = {
                    'duration_seconds': duration,
                    'request_count': len(requests),
                    'unique_pages': len(session_data['pages']),
                    'avg_time_between_requests': duration / (len(requests) - 1) if len(requests) > 1 else 0
                }
        
        return session_stats
    
    def export_analysis_to_csv(self, analysis_data, filename):
        """Export analysis results to CSV"""
        filepath = Path(filename)
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write different sections of analysis
                for section_name, section_data in analysis_data.items():
                    writer.writerow([f"=== {section_name.upper()} ==="])
                    
                    if isinstance(section_data, dict):
                        for key, value in section_data.items():
                            writer.writerow([key, value])
                    elif isinstance(section_data, list):
                        for item in section_data:
                            if isinstance(item, tuple):
                                writer.writerow(list(item))
                            else:
                                writer.writerow([item])
                    
                    writer.writerow([])  # Empty row for separation
        except IOError as e:
            print(f"Error writing CSV file {filename}: {e}")
            raise
    
    def export_analysis_to_json(self, analysis_data, filename):
        """Export analysis results to JSON format
        
        Args:
            analysis_data: Dictionary containing analysis results
            filename: Path to output JSON file
        """
        filepath = Path(filename)
        
        try:
            # Convert Counter objects and other non-serializable types to dicts/lists
            serializable_data = self._make_json_serializable(analysis_data)
            
            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(serializable_data, jsonfile, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error writing JSON file {filename}: {e}")
            raise
    
    def _make_json_serializable(self, data):
        """Convert data structures to JSON-serializable format"""
        if isinstance(data, dict):
            return {key: self._make_json_serializable(value) for key, value in data.items()}
        elif isinstance(data, (list, tuple)):
            return [self._make_json_serializable(item) for item in data]
        elif isinstance(data, Counter):
            return dict(data)
        elif isinstance(data, set):
            return list(data)
        else:
            return data
