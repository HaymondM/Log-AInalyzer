# Python Log Analyzer

A comprehensive log analyzer tool with security-focused threat detection capabilities. Built to identify attack patterns, suspicious behavior, and prepare for AI-powered analysis.

## Features

### Basic Analysis
- Parse common log formats (Apache/Nginx access logs, application logs, syslog)
- Basic statistics and summaries
- Search functionality with regex support
- Filter by log level and time ranges
- Command-line interface

### Core Analysis Features
- **Time-based Analysis**: Peak hours, daily patterns, request distribution over time
- **User Agent Analysis**: Browser detection, OS identification, device classification
- **Performance Metrics**: Response times, percentiles, slow request identification
- **Geographic Analysis**: IP-based region estimation, request patterns by location
- **File Access Patterns**: Static vs dynamic content, file type analysis, API endpoint identification
- **Session Tracking**: User session duration, request patterns, page views per session
- **Export Capabilities**: CSV and JSON export for further analysis

### Security Analysis
- **Attack Pattern Detection**: SQL injection, XSS, path traversal, command injection
- **Brute Force Detection**: Identify repeated failed login attempts
- **Rate Limiting**: Detect potential DDoS or excessive request patterns
- **Suspicious User Agents**: Flag known attack tools (sqlmap, nikto, etc.)
- **Baseline Establishment**: Learn normal behavior patterns
- **Anomaly Detection**: Identify unusual activity based on baselines
- **Comprehensive Reporting**: Detailed security threat summaries

## Usage

### Basic Analysis
```bash
python log_analyzer.py sample_access.log
```

### Core Analysis
```bash
# Comprehensive core analysis
python log_analyzer.py sample_access.log --core-analysis

# Export analysis to JSON
python log_analyzer.py sample_access.log --core-analysis --export-json report.json

# Export analysis to CSV
python log_analyzer.py sample_access.log --core-analysis --export-csv report.csv

# Specific analysis types
python log_analyzer.py sample_access.log --time-analysis
python log_analyzer.py sample_access.log --user-agents
python log_analyzer.py sample_access.log --performance
```

### Security Analysis
```bash
# Full analysis with security report
python log_analyzer.py sample_access.log --security

# Security threats only (no basic stats)
python log_analyzer.py sample_access.log --threats-only
```

### Search for Patterns
```bash
python log_analyzer.py sample_access.log --search "404|500"
```

### Filter by Log Level
```bash
python log_analyzer.py sample_app.log --level ERROR
```

## Core Analysis Features

### Time-based Analysis
- **Peak Activity Detection**: Identifies busiest hours and days
- **Hourly Distribution**: Request patterns throughout the day
- **Daily Patterns**: Traffic trends over multiple days
- **Day-of-week Analysis**: Weekly usage patterns

### User Agent Analysis
- **Browser Detection**: Chrome, Firefox, Safari, Edge identification
- **Operating System**: Windows, macOS, Linux, mobile OS detection
- **Device Classification**: Desktop, mobile, tablet, bot categorization
- **Tool Detection**: Automated tools and scanners

### Performance Metrics
- **Response Time Analysis**: Average, min, max response times
- **Percentile Analysis**: 95th and 99th percentile performance
- **Slow Request Detection**: Requests exceeding thresholds
- **Path Performance**: Slowest endpoints and resources

### Geographic Analysis
- **IP Address Patterns**: Unique visitor identification
- **Regional Estimation**: Basic geographic classification
- **Request Distribution**: Traffic patterns by location
- **Suspicious IP Detection**: Unusual geographic activity

### File Access Patterns
- **Content Classification**: Static vs dynamic content analysis
- **File Type Analysis**: Most requested file extensions
- **HTTP Method Usage**: GET, POST, PUT, DELETE distribution
- **API Endpoint Detection**: REST API usage patterns

### Session Tracking
- **Session Duration**: User engagement time analysis
- **Request Patterns**: Requests per session statistics
- **Page Views**: Unique pages visited per session
- **User Journey**: Basic navigation pattern analysis

## Generate Sample Data

Create sample log files with security threats for testing:
```bash
python sample_logs.py
```

## Future AI Features

The analyzer is designed to be extended with AI capabilities for:
- Advanced anomaly detection using machine learning
- Behavioral pattern analysis
- Predictive threat modeling
- Automated incident response
- Custom threat signature learning

## Security Features

### Detected Threats
- **SQL Injection**: `UNION SELECT`, `OR 1=1`, `DROP TABLE`
- **XSS Attempts**: `<script>`, `javascript:`, `alert()`
- **Path Traversal**: `../../../`, `/etc/passwd`, `windows/system32`
- **Command Injection**: `;cat`, `|ls`, `$(command)`
- **Brute Force**: Multiple failed authentication attempts
- **Suspicious Tools**: sqlmap, nikto, nmap, automated scanners

### Security Reports Include
- Threat counts by severity (critical, high, medium, low)
- Top attacking IP addresses
- Brute force attempt summaries
- Rate limiting violations
- Behavioral anomalies
- Detailed threat breakdowns

## File Structure

- `log_analyzer.py` - Main analyzer class and CLI
- `core_analyzer.py` - Core analysis features (time, performance, geographic)
- `security_analyzer.py` - Security threat detection engine
- `sample_logs.py` - Generate test data with security threats
- `requirements.txt` - Dependencies (currently minimal)