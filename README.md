# Python Log Analyzer

A comprehensive log analyzer tool with security-focused threat detection capabilities. Built to identify attack patterns, suspicious behavior, and prepare for AI-powered analysis.

## Features

### Basic Analysis
- Parse common log formats (Apache/Nginx access logs, application logs, syslog)
- Basic statistics and summaries
- Search functionality with regex support
- Filter by log level and time ranges
- Command-line interface

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

## File Structure

- `log_analyzer.py` - Main analyzer class and CLI
- `security_analyzer.py` - Security threat detection engine
- `sample_logs.py` - Generate test data with security threats
- `requirements.txt` - Dependencies (currently minimal)