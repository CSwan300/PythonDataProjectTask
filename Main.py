import re
import os
import matplotlib.pyplot as plt
from datetime import datetime
import requests
from collections import defaultdict, Counter
import numpy as np

# GitHub raw URL for the log file
GITHUB_LOG_URL = "https://raw.githubusercontent.com/brightnetwork/ieuk-task-2025/main/sample-log.log"
LOCAL_LOG_FILE = "sample-log.log"


def download_log_file():
    """Download the log file from GitHub if it doesn't exist locally"""
    if not os.path.exists(LOCAL_LOG_FILE):
        print(f"Downloading log file from GitHub...")
        try:
            response = requests.get(GITHUB_LOG_URL)
            response.raise_for_status()  # Raise error for bad status

            with open(LOCAL_LOG_FILE, 'w') as f:
                f.write(response.text)
            print(f"Log file downloaded successfully: {LOCAL_LOG_FILE}")
            return True
        except Exception as e:
            print(f"Error downloading log file: {e}")
            return False
    return True


def is_bot(user_agent):
    """Detect if the request comes from a bot/crawler"""
    if not user_agent or user_agent == '-':
        return False

    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'feed', 'crawl',
        'google', 'bing', 'yahoo', 'baidu', 'yandex', 'duckduck',
        'slurp', 'teoma', 'ask jeeves', 'curl', 'wget', 'python-requests',
        'java', 'httpclient', 'apache-httpclient', 'php', 'ruby', 'go-http',
        'node-fetch', 'okhttp', 'libwww', 'zgrab', 'panscient', 'nmap'
    ]

    ua_lower = user_agent.lower()
    return any(indicator in ua_lower for indicator in bot_indicators)


def analyze_log_line(line):
    problems = []
    bot_detected = False
    bot_name = None

    pattern = r'^(\S+) - (\S+) - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)" (\d+)$'
    match = re.match(pattern, line.strip())

    if not match:
        return ["Malformed log entry"], None, False, None

    ip, auth, timestamp, method, path, protocol, status, bytes_sent, referer, user_agent, response_time = match.groups()

    # Convert numerical values
    try:
        status_code = int(status)
        response_time_ms = int(response_time)
        bytes_transferred = int(bytes_sent)
    except ValueError:
        problems.append("Invalid numerical values")
        return problems, None, False, None

    # Bot detection
    if is_bot(user_agent):
        bot_detected = True
        # Try to extract bot name
        if 'bot' in user_agent.lower():
            bot_match = re.search(r'(\w+bot/\d+\.\d+|\w+bot)', user_agent, re.IGNORECASE)
            if bot_match:
                bot_name = bot_match.group(1)
        elif 'google' in user_agent.lower():
            bot_name = 'Googlebot'
        elif 'bing' in user_agent.lower():
            bot_name = 'Bingbot'
        elif 'yahoo' in user_agent.lower():
            bot_name = 'Yahoo Slurp'
        else:
            bot_name = "Unknown Bot"

        problems.append("Bot detected")

    # Status code checks
    if 400 <= status_code < 500:
        problems.append(f"Client error ({status_code})")
    elif 500 <= status_code < 600:
        problems.append(f"Server error ({status_code})")

    # Slow response
    if response_time_ms > 500:
        problems.append(f"Slow response (>500ms)")

    # Missing user agent
    if user_agent in ('-', ''):
        problems.append("Missing user agent")

    # Suspicious paths
    suspicious_paths = r'(admin|login|wp-admin|\.php|\.env|config|\.\./|/cgi-bin/)'
    if re.search(suspicious_paths, path, re.IGNORECASE):
        problems.append(f"Suspicious path")

    # Authentication failures
    if auth == 'NO':
        problems.append("Authentication failed")

    # Timestamp validation
    try:
        datetime.strptime(timestamp, '%d/%m/%Y:%H:%M:%S')
    except ValueError:
        problems.append(f"Invalid timestamp")

    # Unusually large transfers
    if bytes_transferred > 1000000:  # 1MB
        problems.append(f"Large transfer (>1MB)")

    # Return both problems and the parsed data for visualization
    data_point = {
        'status': status_code,
        'response_time': response_time_ms,
        'bytes': bytes_transferred,
        'path': path,
        'method': method,
        'ip': ip,
        'user_agent': user_agent
    }

    return problems, data_point, bot_detected, bot_name


def visualize_data(problem_counts, status_codes, response_times, total_lines,
                   suspicious_paths, top_ips, bot_stats, bot_types):
    # Create figure with 3 subplots
    plt.figure(figsize=(18, 15))
    plt.suptitle(f"Log Analysis Summary ({total_lines} entries)", fontsize=16)

    # Problem Type Distribution (Bar Chart)
    plt.subplot(3, 3, 1)
    if problem_counts:
        problems, counts = zip(*sorted(problem_counts.items(), key=lambda x: x[1], reverse=True)[:8])
        plt.bar(problems, counts, color='salmon')
        plt.title('Top 8 Issues Detected')
        plt.xticks(rotation=45, ha='right', fontsize=9)
        plt.ylabel('Count')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
    else:
        plt.text(0.5, 0.5, 'No issues detected',
                 ha='center', va='center', fontsize=12)
        plt.title('No Issues Found')

    # Status Code Distribution (Pie Chart)
    plt.subplot(3, 3, 2)
    if status_codes:
        # Group status codes into categories
        status_groups = {
            '2xx Success': sum(count for code, count in status_codes.items() if 200 <= code < 300),
            '3xx Redirection': sum(count for code, count in status_codes.items() if 300 <= code < 400),
            '4xx Client Error': sum(count for code, count in status_codes.items() if 400 <= code < 500),
            '5xx Server Error': sum(count for code, count in status_codes.items() if 500 <= code < 600),
            'Other': sum(count for code, count in status_codes.items() if code < 200 or code >= 600)
        }

        colors = ['#4CAF50', '#FFC107', '#FF9800', '#F44336', '#9E9E9E']
        plt.pie(
            status_groups.values(),
            labels=status_groups.keys(),
            autopct='%1.1f%%',
            startangle=90,
            colors=colors,
            shadow=True,
            explode=(0.05, 0.05, 0.05, 0.05, 0.05)
        )
        plt.title('Status Code Distribution')
        plt.axis('equal')
    else:
        plt.text(0.5, 0.5, 'No status data',
                 ha='center', va='center', fontsize=12)
        plt.title('No Status Codes Found')

    # Response Time Distribution (Histogram)
    plt.subplot(3, 3, 3)
    if response_times:
        plt.hist(response_times, bins=50, color='#2196F3', edgecolor='black')
        plt.title('Response Time Distribution')
        plt.xlabel('Response Time (ms)')
        plt.ylabel('Frequency')
        plt.axvline(x=500, color='r', linestyle='--', label='500ms threshold')
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.yscale('log')
    else:
        plt.text(0.5, 0.5, 'No response time data',
                 ha='center', va='center', fontsize=12)
        plt.title('No Response Times Found')

    # Suspicious Paths (Bar Chart)
    plt.subplot(3, 3, 4)
    if suspicious_paths:
        paths, counts = zip(*suspicious_paths.most_common(8))
        plt.barh(paths, counts, color='#FF5722')
        plt.title('Top Suspicious Paths')
        plt.xlabel('Access Count')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
    else:
        plt.text(0.5, 0.5, 'No suspicious paths',
                 ha='center', va='center', fontsize=12)
        plt.title('No Suspicious Paths Found')

    # Top IP Addresses
    plt.subplot(3, 3, 5)
    if top_ips:
        ips, counts = zip(*top_ips.most_common(8))
        plt.barh(ips, counts, color='#9C27B0')
        plt.title('Top Client IP Addresses')
        plt.xlabel('Request Count')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
    else:
        plt.text(0.5, 0.5, 'No IP data',
                 ha='center', va='center', fontsize=12)
        plt.title('No IP Addresses Found')

    # HTTP Methods
    plt.subplot(3, 3, 6)
    if hasattr(visualize_data, 'http_methods') and visualize_data.http_methods:
        methods, counts = zip(*visualize_data.http_methods.items())
        plt.pie(counts, labels=methods, autopct='%1.1f%%',
                startangle=90, colors=plt.cm.Pastel1.colors)
        plt.title('HTTP Method Distribution')
        plt.axis('equal')
    else:
        plt.text(0.5, 0.5, 'No method data',
                 ha='center', va='center', fontsize=12)
        plt.title('No HTTP Methods Found')

    # Bot Traffic Analysis
    plt.subplot(3, 3, 7)
    if bot_stats['total_bots'] > 0:
        labels = ['Human Traffic', 'Bot Traffic']
        sizes = [total_lines - bot_stats['total_bots'], bot_stats['total_bots']]
        colors = ['#66b3ff', '#ff9999']
        explode = (0.1, 0)  # explode the bot slice
        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')
        plt.title('Bot vs Human Traffic')
    else:
        plt.text(0.5, 0.5, 'No bot traffic detected',
                 ha='center', va='center', fontsize=12)
        plt.title('No Bot Traffic')

    # Top Bot Types
    plt.subplot(3, 3, 8)
    if bot_types:
        bots, counts = zip(*bot_types.most_common(8))
        plt.bar(bots, counts, color='#FF9800')
        plt.title('Top Bot Types')
        plt.xticks(rotation=45, ha='right', fontsize=9)
        plt.ylabel('Request Count')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
    else:
        plt.text(0.5, 0.5, 'No bot data',
                 ha='center', va='center', fontsize=12)
        plt.title('No Bot Types Found')

    # Bot Status Codes
    plt.subplot(3, 3, 9)
    if hasattr(visualize_data, 'bot_status_codes') and visualize_data.bot_status_codes:
        codes, counts = zip(*sorted(visualize_data.bot_status_codes.items()))
        plt.bar(codes, counts, color='#4CAF50')
        plt.title('Bot Response Status Codes')
        plt.xlabel('HTTP Status Code')
        plt.ylabel('Count')
        plt.grid(axis='y', linestyle='--', alpha=0.7)

        # Annotate each bar with its count
        for i, v in enumerate(counts):
            plt.text(i, v + 0.5, str(v), ha='center', fontsize=9)
    else:
        plt.text(0.5, 0.5, 'No bot status data',
                 ha='center', va='center', fontsize=12)
        plt.title('No Bot Status Codes')

    plt.tight_layout(rect=[0, 0, 1, 0.96])

    # Save and show
    plt.savefig('log_analysis_report.png', dpi=150)
    print("Visualization saved as 'log_analysis_report.png'")
    plt.show()


def main():
    # Download or use local log file
    if not download_log_file():
        print("Analysis aborted due to missing log file.")
        return

    print(f"Analyzing log file: {LOCAL_LOG_FILE}")
    total_lines = 0
    problem_lines = 0
    problem_counts = Counter()
    status_codes = Counter()
    response_times = []
    suspicious_paths = Counter()
    ip_addresses = Counter()
    http_methods = Counter()

    # Bot statistics
    bot_stats = {
        'total_bots': 0,
        'bot_ips': Counter(),
        'bot_paths': Counter(),
        'bot_status_codes': Counter()
    }
    bot_types = Counter()

    # Store problematic entries for output
    problematic_entries = []

    with open(LOCAL_LOG_FILE, 'r') as file:
        for line_number, line in enumerate(file, 1):
            total_lines += 1
            issues, data_point, is_bot, bot_name = analyze_log_line(line)

            # Collect data for visualization
            if data_point:
                # Status code distribution
                status_codes[data_point['status']] += 1

                # Response times
                response_times.append(data_point['response_time'])

                # Track suspicious paths
                if 'Suspicious path' in issues:
                    suspicious_paths[data_point['path']] += 1

                # Track IP addresses
                ip_addresses[data_point['ip']] += 1

                # Track HTTP methods
                http_methods[data_point['method']] += 1

                # Bot-specific tracking
                if is_bot:
                    bot_stats['total_bots'] += 1
                    bot_stats['bot_ips'][data_point['ip']] += 1
                    bot_stats['bot_paths'][data_point['path']] += 1
                    bot_stats['bot_status_codes'][data_point['status']] += 1

                    if bot_name:
                        bot_types[bot_name] += 1

            if issues:
                problem_lines += 1
                problem_counts.update(issues)

                # Store request details and issues
                if data_point:
                    entry = {
                        'line': line_number,
                        'ip': data_point['ip'],
                        'method': data_point['method'],
                        'path': data_point['path'],
                        'status': data_point['status'],
                        'response_time': data_point['response_time'],
                        'bytes': data_point['bytes'],
                        'issues': list(issues)  # Convert set to list
                    }
                    problematic_entries.append(entry)

    # Attach additional data to visualization function
    visualize_data.http_methods = http_methods
    visualize_data.bot_status_codes = bot_stats['bot_status_codes']

    # Print summary
    print("\nAnalysis Summary:")
    print(f"Total lines processed: {total_lines}")
    print(f"Problematic lines found: {problem_lines}")
    print(f"Bot traffic detected: {bot_stats['total_bots']} ({bot_stats['total_bots'] / total_lines * 100:.2f}%)")

    if total_lines > 0:
        print(f"Percentage problematic: {problem_lines / total_lines * 100:.2f}%")

    # Print top problems if any
    if problem_counts:
        print("\nTop Issues:")
        for issue, count in problem_counts.most_common(10):
            print(f"  {issue}: {count} occurrences")

    # Get top IP addresses
    top_ips = ip_addresses.most_common(8)
    if top_ips:
        print("\nTop Client IP Addresses:")
        for ip, count in top_ips:
            print(f"  {ip}: {count} requests")

    # Bot summary
    if bot_stats['total_bots'] > 0:
        print("\nBot Traffic Analysis:")
        print(f"Total bot requests: {bot_stats['total_bots']}")
        print(f"Top bot types: {bot_types.most_common(5)}")
        print(f"Top bot IPs: {bot_stats['bot_ips'].most_common(5)}")
        print(f"Top paths accessed by bots: {bot_stats['bot_paths'].most_common(5)}")
        print(f"Bot status codes: {bot_stats['bot_status_codes'].most_common(5)}")

    # Print problematic HTTP requests
    if problematic_entries:
        print("\nProblematic HTTP Requests (First 10):")
        print("Line | IP Address    | Method | Path                 | Status | Time(ms) | Size   | Issues")
        print("-" * 95)

        for entry in problematic_entries[:10]:
            print(
                f"{entry['line']:<4} | {entry['ip']:<13} | {entry['method']:<6} | "
                f"{entry['path'][:20]:<20} | {entry['status']:<6} | "
                f"{entry['response_time']:<8} | {entry['bytes']:<6} | {', '.join(entry['issues'][:2])}"
            )

        # Save full report to file
        with open('problematic_requests.log', 'w') as f:
            f.write("Full List of Problematic Requests:\n")
            f.write("Line | IP Address    | Method | Path                 | Status | Time(ms) | Size   | Issues\n")
            f.write("-" * 95 + "\n")
            for entry in problematic_entries:
                f.write(
                    f"{entry['line']:<4} | {entry['ip']:<13} | {entry['method']:<6} | "
                    f"{entry['path'][:20]:<20} | {entry['status']:<6} | "
                    f"{entry['response_time']:<8} | {entry['bytes']:<6} | {', '.join(entry['issues'])}\n"
                )
        print(f"\nSaved full report of {len(problematic_entries)} problematic requests to 'problematic_requests.log'")
    else:
        print("\nNo problematic requests found")

    # Generate visualizations
    try:
        import matplotlib
        print("\nGenerating visualizations...")
        visualize_data(problem_counts, status_codes, response_times, total_lines,
                       suspicious_paths, Counter(ip_addresses), bot_stats, bot_types)
    except ImportError:
        print("\nVisualization skipped: matplotlib not installed.")
        print("Install it with: pip install matplotlib")


if __name__ == "__main__":
    # Install requests if needed
    try:
        import requests
    except ImportError:
        print("Installing required module: requests")
        import subprocess

        subprocess.check_call(["pip", "install", "requests"])
        import requests

    main()