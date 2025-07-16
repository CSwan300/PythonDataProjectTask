# Log Analysis and Visualization Tool
### Extra info 
AI was used in the creation off the project as this was my first time ever using Matlabplot or python for Data Analysis
Ai was also used to help me troubleshoot the docker implementation

## Overview
This Python-based log analysis tool processes web server log files, detects potential issues, and generates detailed reports with visualizations. It analyzes:
- Bot traffic patterns
- HTTP errors (client/server)
- Suspicious access patterns
- Performance issues (slow responses)
- Large file transfers
- Authentication failures
- Malformed log entries
  

## Key Features
- **Bot Detection**: Identifies crawlers/spiders and categorizes bot types
- **Anomaly Detection**: Flags suspicious activities and errors
- **Performance Metrics**: Tracks response times and large transfers
- **Visual Reporting**: Generates 9 comprehensive visualizations
- **GitHub Integration**: Automatically downloads sample logs
- **Detailed Reporting**: Creates text reports of problematic requests

## Installation
1. **Prerequisites**: Python 3.11+
```bash
# Install required dependencies
pip install requests matplotlib
```
## Customization
Use custom logs:

Replace sample-log.log with your log file

## Docker 
I have no idea how you could run this in docker non locally as this was my frist ever experience off docker and matlabplot in python.
