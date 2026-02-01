# Python Log Analyzer

A basic log analyzer tool that can parse and analyze various log file formats. Built to be extensible for future AI-powered suspicious behavior detection.

## Features

- Parse common log formats (Apache/Nginx access logs, application logs, syslog)
- Basic statistics and summaries
- Search functionality with regex support
- Filter by log level and time ranges
- Command-line interface

## Usage

### Basic Analysis
```bash
python log_analyzer.py sample_access.log
```

### Search for Patterns
```bash
python log_analyzer.py sample_access.log --search "404|500"
```

### Filter by Log Level
```bash
python log_analyzer.py sample_app.log --level ERROR
```

## Generate Sample Data

Create sample log files for testing:
```bash
python sample_logs.py
```

## Future AI Features

The analyzer is designed to be extended with AI capabilities for:
- Anomaly detection
- Suspicious behavior pattern recognition
- Automated threat classification
- Predictive analysis

## File Structure

- `log_analyzer.py` - Main analyzer class and CLI
- `sample_logs.py` - Generate test data
- `requirements.txt` - Dependencies (currently minimal)