"""
Web Server Log Analysis Tool

Analyzes web server log files to identify issues, suspicious activities,
and traffic patterns. Performs both technical analysis and visualization.

Key Features:
- Automated log file download from GitHub (streamed, size-limited)
- Single-pass IP counting + deferred flagging
- Bot detection using user agent analysis
- Suspicious activity identification
- Comprehensive visualization dashboard
- Detailed text reporting
"""

import re
import os
import logging
from datetime import datetime
from dataclasses import dataclass
from collections import Counter
from typing import Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend — must be set before importing pyplot
import matplotlib.pyplot as plt
import requests

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

GITHUB_LOG_URL = "https://raw.githubusercontent.com/brightnetwork/ieuk-task-2025/main/sample-log.log"
LOCAL_LOG_FILE = "sample-log.log"

OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "output")

HIGH_REQUEST_THRESHOLD = 30
SLOW_RESPONSE_MS = 500
LARGE_TRANSFER_BYTES = 1_000_000
DOWNLOAD_TIMEOUT_S = 30
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

# ---------------------------------------------------------------------------
# Compiled regex patterns (compiled once at import time)
# ---------------------------------------------------------------------------

LOG_PATTERN = re.compile(
    r'^(\S+) - (\S+) - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+) "([^"]*)" "([^"]*)" (\d+)$'
)

SUSPICIOUS_PATH_RE = re.compile(
    r'(admin|login|wp-admin|\.php|\.env|config|\.\./|/cgi-bin/)',
    re.IGNORECASE,
)

BOT_RE = re.compile(
    r'\b(bot|crawler|spider|scraper|feed|crawl|slurp|teoma|curl|wget|'
    r'python-requests|httpclient|apache-httpclient|node-fetch|okhttp|'
    r'libwww|zgrab|panscient|nmap)\b|'
    r'(google|bing|yahoo|baidu|yandex|duckduck|go-http|php|ruby|java)',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
#These can be configured
class LogEntry:
    ip: str
    auth: str
    timestamp: str
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str
    response_time: int


@dataclass
class AnalysisResult:
    total_lines: int
    problem_lines: int
    problem_counts: Counter
    status_codes: Counter
    response_times: list
    suspicious_paths: Counter
    ip_addresses: Counter
    http_methods: Counter
    bot_stats: dict
    bot_types: Counter
    problematic_entries: list


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_log_file() -> bool:
    """
    Stream the log file from GitHub if it does not exist locally.
    Enforces a timeout and a maximum file size.

    Returns:
        True if the file is available, False otherwise.
    """
    if os.path.exists(LOCAL_LOG_FILE):
        return True

    log.info("Downloading log file from GitHub...")
    try:
        with requests.get(GITHUB_LOG_URL, stream=True, timeout=DOWNLOAD_TIMEOUT_S) as response:
            response.raise_for_status()
            with open(LOCAL_LOG_FILE, "wb") as f:
                downloaded = 0
                for chunk in response.iter_content(chunk_size=65_536):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if downloaded > MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"Log file exceeds the {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB size limit."
                        )
        log.info("Download complete: %s", LOCAL_LOG_FILE)
        return True
    except Exception as exc:
        log.error("Failed to download log file: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Bot detection
# ---------------------------------------------------------------------------

def is_bot(user_agent: str) -> bool:
    """
    Detect whether a request comes from a bot/crawler.

    Uses word-boundary matching to reduce false positives from
    substrings (e.g. 'java' inside a legitimate browser UA).

    Args:
        user_agent: The User-Agent header string.

    Returns:
        True if a bot pattern is detected.
    """
    if not user_agent or user_agent == "-":
        return False
    return bool(BOT_RE.search(user_agent))


def extract_bot_name(user_agent: str) -> str:
    """
    Return a human-readable name for a detected bot.

    Args:
        user_agent: The User-Agent header string.

    Returns:
        A short bot name string.
    """
    ua_lower = user_agent.lower()
    if "google" in ua_lower:
        return "Googlebot"
    if "bing" in ua_lower:
        return "Bingbot"
    if "yahoo" in ua_lower:
        return "Yahoo Slurp"
    if "baidu" in ua_lower:
        return "Baiduspider"
    if "yandex" in ua_lower:
        return "YandexBot"
    bot_match = re.search(r'(\w+bot/[\d.]+|\w+bot)', user_agent, re.IGNORECASE)
    if bot_match:
        return bot_match.group(1)
    return "Unknown Bot"


# ---------------------------------------------------------------------------
# Log line parsing
# ---------------------------------------------------------------------------

def parse_log_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single log line into a LogEntry dataclass.

    Args:
        line: A raw log line string.

    Returns:
        A LogEntry on success, or None if the line is malformed.
    """
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None

    ip, auth, timestamp, method, path, protocol, status, bytes_sent, referer, user_agent, response_time = match.groups()

    try:
        return LogEntry(
            ip=ip,
            auth=auth,
            timestamp=timestamp,
            method=method,
            path=path,
            protocol=protocol,
            status=int(status),
            bytes_sent=int(bytes_sent),
            referer=referer,
            user_agent=user_agent,
            response_time=int(response_time),
        )
    except ValueError:
        return None


def detect_issues(entry: LogEntry, high_request_ips: set) -> list:
    """
    Return a list of issue strings for a parsed log entry.

    Args:
        entry:            A parsed LogEntry.
        high_request_ips: Set of IPs that have exceeded the request threshold.

    Returns:
        A list of issue description strings (may be empty).
    """
    issues = []

    if entry.ip in high_request_ips:
        issues.append("High request count (potential bot)")

    if is_bot(entry.user_agent):
        issues.append("Bot detected")

    if 400 <= entry.status < 500:
        issues.append(f"Client error ({entry.status})")
    elif 500 <= entry.status < 600:
        issues.append(f"Server error ({entry.status})")

    if entry.response_time > SLOW_RESPONSE_MS:
        issues.append("Slow response (>500ms)")

    if entry.user_agent in ("-", ""):
        issues.append("Missing user agent")

    if SUSPICIOUS_PATH_RE.search(entry.path):
        issues.append("Suspicious path")

    if entry.auth == "NO":
        issues.append("Authentication failed")

    try:
        datetime.strptime(entry.timestamp, "%d/%m/%Y:%H:%M:%S")
    except ValueError:
        issues.append("Invalid timestamp")

    if entry.bytes_sent > LARGE_TRANSFER_BYTES:
        issues.append("Large transfer (>1MB)")

    return issues


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def collect_ip_counts(filepath: str) -> Counter:
    """
    Single-pass collection of per-IP request counts.

    Args:
        filepath: Path to the log file.

    Returns:
        A Counter mapping IP address to request count.
    """
    ip_re = re.compile(r'^(\S+) -')
    counts = Counter()
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = ip_re.match(line)
            if m:
                counts[m.group(1)] += 1
    return counts


def analyse_entries(filepath: str, high_request_ips: set) -> AnalysisResult:
    """
    Full analysis pass over the log file.

    Args:
        filepath:         Path to the log file.
        high_request_ips: Pre-computed set of high-volume IPs.

    Returns:
        A populated AnalysisResult dataclass.
    """
    total_lines = 0
    problem_lines = 0
    problem_counts = Counter()
    status_codes = Counter()
    response_times = []
    suspicious_paths = Counter()
    ip_addresses = Counter()
    http_methods = Counter()
    bot_stats = {
        "total_bots": 0,
        "bot_ips": Counter(),
        "bot_paths": Counter(),
        "bot_status_codes": Counter(),
        "high_request_bots": 0,
    }
    bot_types = Counter()
    problematic_entries = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, 1):
            total_lines += 1

            entry = parse_log_line(line)
            if entry is None:
                problem_lines += 1
                problem_counts["Malformed log entry"] += 1
                continue

            ip_addresses[entry.ip] += 1
            status_codes[entry.status] += 1
            response_times.append(entry.response_time)
            http_methods[entry.method] += 1

            bot_detected = is_bot(entry.user_agent)
            is_high_req = entry.ip in high_request_ips

            if bot_detected:
                bot_stats["total_bots"] += 1
                bot_stats["bot_ips"][entry.ip] += 1
                bot_stats["bot_paths"][entry.path] += 1
                bot_stats["bot_status_codes"][entry.status] += 1
                bot_types[extract_bot_name(entry.user_agent)] += 1

            if is_high_req and not bot_detected:
                bot_stats["high_request_bots"] += 1

            if SUSPICIOUS_PATH_RE.search(entry.path):
                suspicious_paths[entry.path] += 1

            issues = detect_issues(entry, high_request_ips)

            if issues:
                problem_lines += 1
                problem_counts.update(issues)
                problematic_entries.append({
                    "line": line_number,
                    "ip": entry.ip,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "response_time": entry.response_time,
                    "bytes": entry.bytes_sent,
                    "issues": list(set(issues)),
                })

    return AnalysisResult(
        total_lines=total_lines,
        problem_lines=problem_lines,
        problem_counts=problem_counts,
        status_codes=status_codes,
        response_times=response_times,
        suspicious_paths=suspicious_paths,
        ip_addresses=ip_addresses,
        http_methods=http_methods,
        bot_stats=bot_stats,
        bot_types=bot_types,
        problematic_entries=problematic_entries,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(result: AnalysisResult) -> None:
    """
    Print a summary of the analysis results.

    Args:
        result: A completed AnalysisResult.
    """
    t = result.total_lines
    b = result.bot_stats

    log.info("Analysis Summary")
    log.info("  Total lines processed : %d", t)
    log.info("  Problematic lines     : %d", result.problem_lines)

    if t > 0:
        log.info("  Known bots            : %d (%.2f%%)", b["total_bots"], b["total_bots"] / t * 100)
        log.info("  High-request IPs      : %d (%.2f%%)", b["high_request_bots"], b["high_request_bots"] / t * 100)
        log.info("  Percentage problematic: %.2f%%", result.problem_lines / t * 100)

    if result.problem_counts:
        log.info("Top issues:")
        for issue, count in result.problem_counts.most_common(10):
            log.info("    %-40s %d", issue, count)

    if result.ip_addresses:
        log.info("Top client IP addresses:")
        for ip, count in result.ip_addresses.most_common(8):
            log.info("    %-18s %d requests", ip, count)

    if b["total_bots"] > 0 or b["high_request_bots"] > 0:
        log.info("Bot traffic analysis:")
        log.info("  Total bot requests : %d", b["total_bots"])
        log.info("  High-request IPs   : %d", b["high_request_bots"])
        log.info("  Top bot types      : %s", result.bot_types.most_common(5))
        log.info("  Top bot IPs        : %s", b["bot_ips"].most_common(5))
        log.info("  Top bot paths      : %s", b["bot_paths"].most_common(5))
        log.info("  Bot status codes   : %s", b["bot_status_codes"].most_common(5))


def save_problematic_report(result: AnalysisResult) -> None:
    """
    Save the full list of problematic requests to a log file in OUTPUT_DIR.

    Args:
        result: A completed AnalysisResult.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "problematic_requests.log")

    entries = result.problematic_entries
    if not entries:
        log.info("No problematic requests found.")
        return

    header = (
        "Line | IP Address        | Method | Path                 "
        "| Status | Time(ms) | Size   | Issues\n"
        + "-" * 100 + "\n"
    )

    log.info("Problematic HTTP requests (first 10):")
    log.info(header.rstrip())
    for entry in entries[:10]:
        log.info(
            "%4d | %-17s | %-6s | %-20s | %-6d | %-8d | %-6d | %s",
            entry["line"], entry["ip"], entry["method"],
            entry["path"][:20], entry["status"],
            entry["response_time"], entry["bytes"],
            ", ".join(entry["issues"][:2]),
        )

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("Full List of Problematic Requests:\n")
        f.write(header)
        for entry in entries:
            f.write(
                f"{entry['line']:<4} | {entry['ip']:<17} | {entry['method']:<6} | "
                f"{entry['path'][:20]:<20} | {entry['status']:<6} | "
                f"{entry['response_time']:<8} | {entry['bytes']:<6} | "
                f"{', '.join(entry['issues'])}\n"
            )

    log.info("Saved full report of %d entries to '%s'", len(entries), out_path)


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def visualize_data(result: AnalysisResult) -> None:
    """
    Generate and save a 3x3 visualisation dashboard as a PNG into OUTPUT_DIR.

    Args:
        result: A completed AnalysisResult.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "log_analysis_report.png")

    t = result.total_lines
    bot_stats = result.bot_stats

    fig, axes = plt.subplots(3, 3, figsize=(18, 15))
    fig.suptitle(f"Log Analysis Summary ({t} entries)", fontsize=16)

    # 1. Problem type distribution
    ax = axes[0, 0]
    if result.problem_counts:
        items = sorted(result.problem_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        problems, counts = zip(*items)
        ax.bar(problems, counts, color="salmon")
        ax.set_title("Top 8 issues detected")
        ax.set_ylabel("Count")
        ax.tick_params(axis="x", rotation=45, labelsize=9)
        ax.grid(axis="y", linestyle="--", alpha=0.7)
    else:
        ax.text(0.5, 0.5, "No issues detected", ha="center", va="center")
        ax.set_title("No issues found")

    # 2. Status code distribution
    ax = axes[0, 1]
    if result.status_codes:
        status_groups = {
            "2xx Success":    sum(c for code, c in result.status_codes.items() if 200 <= code < 300),
            "3xx Redirect":   sum(c for code, c in result.status_codes.items() if 300 <= code < 400),
            "4xx Client err": sum(c for code, c in result.status_codes.items() if 400 <= code < 500),
            "5xx Server err": sum(c for code, c in result.status_codes.items() if 500 <= code < 600),
            "Other":          sum(c for code, c in result.status_codes.items() if code < 200 or code >= 600),
        }
        # Only pass non-zero slices to avoid explode length mismatch
        non_zero = {k: v for k, v in status_groups.items() if v > 0}
        colors = ["#4CAF50", "#FFC107", "#FF9800", "#F44336", "#9E9E9E"][:len(non_zero)]
        explode = [0.05] * len(non_zero)
        ax.pie(
            non_zero.values(), labels=non_zero.keys(),
            autopct="%1.1f%%", startangle=90,
            colors=colors, shadow=True, explode=explode,
        )
        ax.set_title("Status code distribution")
        ax.axis("equal")
    else:
        ax.text(0.5, 0.5, "No status data", ha="center", va="center")
        ax.set_title("No status codes found")

    # 3. Response time distribution
    ax = axes[0, 2]
    if result.response_times:
        ax.hist(result.response_times, bins=50, color="#2196F3", edgecolor="black")
        ax.set_title("Response time distribution")
        ax.set_xlabel("Response time (ms)")
        ax.set_ylabel("Frequency")
        ax.axvline(x=SLOW_RESPONSE_MS, color="r", linestyle="--", label=f"{SLOW_RESPONSE_MS}ms threshold")
        ax.legend()
        ax.grid(axis="y", linestyle="--", alpha=0.7)
        ax.set_yscale("log")
    else:
        ax.text(0.5, 0.5, "No response time data", ha="center", va="center")
        ax.set_title("No response times found")

    # 4. Suspicious paths
    ax = axes[1, 0]
    if result.suspicious_paths:
        paths, counts = zip(*result.suspicious_paths.most_common(8))
        ax.barh(paths, counts, color="#FF5722")
        ax.set_title("Top suspicious paths")
        ax.set_xlabel("Access count")
        ax.grid(axis="x", linestyle="--", alpha=0.7)
    else:
        ax.text(0.5, 0.5, "No suspicious paths", ha="center", va="center")
        ax.set_title("No suspicious paths found")

    # 5. Top IP addresses
    ax = axes[1, 1]
    if result.ip_addresses:
        ips, counts = zip(*result.ip_addresses.most_common(8))
        ax.barh(ips, counts, color="#9C27B0")
        ax.set_title("Top client IP addresses")
        ax.set_xlabel("Request count")
        ax.grid(axis="x", linestyle="--", alpha=0.7)
    else:
        ax.text(0.5, 0.5, "No IP data", ha="center", va="center")
        ax.set_title("No IP addresses found")

    # 6. HTTP methods
    ax = axes[1, 2]
    if result.http_methods:
        methods, counts = zip(*result.http_methods.items())
        ax.pie(counts, labels=methods, autopct="%1.1f%%",
               startangle=90, colors=plt.cm.Pastel1.colors)
        ax.set_title("HTTP method distribution")
        ax.axis("equal")
    else:
        ax.text(0.5, 0.5, "No method data", ha="center", va="center")
        ax.set_title("No HTTP methods found")

    # 7. Traffic composition
    ax = axes[2, 0]
    human_traffic = t - bot_stats["total_bots"] - bot_stats["high_request_bots"]
    if human_traffic < t:
        sizes = [human_traffic, bot_stats["total_bots"], bot_stats["high_request_bots"]]
        labels = ["Human traffic", "Known bots", "High-request IPs"]
        ax.pie(sizes, explode=(0.1, 0, 0.1), labels=labels,
               colors=["#66b3ff", "#ff9999", "#ffcc99"],
               autopct="%1.1f%%", shadow=True, startangle=90)
        ax.axis("equal")
        ax.set_title("Traffic composition")
    else:
        ax.text(0.5, 0.5, "No bot traffic detected", ha="center", va="center")
        ax.set_title("No bot traffic")

    # 8. Top bot types
    ax = axes[2, 1]
    if result.bot_types:
        bots, counts = zip(*result.bot_types.most_common(8))
        ax.bar(bots, counts, color="#FF9800")
        ax.set_title("Top bot types")
        ax.tick_params(axis="x", rotation=45, labelsize=9)
        ax.set_ylabel("Request count")
        ax.grid(axis="y", linestyle="--", alpha=0.7)
    else:
        ax.text(0.5, 0.5, "No bot data", ha="center", va="center")
        ax.set_title("No bot types found")

    # 9. Bot status codes
    ax = axes[2, 2]
    if bot_stats["bot_status_codes"]:
        codes, counts = zip(*sorted(bot_stats["bot_status_codes"].items()))
        x_pos = range(len(codes))
        ax.bar(x_pos, counts, color="#4CAF50")
        ax.set_xticks(list(x_pos))
        ax.set_xticklabels([str(c) for c in codes])
        ax.set_title("Bot response status codes")
        ax.set_xlabel("HTTP status code")
        ax.set_ylabel("Count")
        ax.grid(axis="y", linestyle="--", alpha=0.7)
        for i, v in enumerate(counts):
            ax.text(i, v + 0.5, str(v), ha="center", fontsize=9)
    else:
        ax.text(0.5, 0.5, "No bot status data", ha="center", va="center")
        ax.set_title("No bot status codes")

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    log.info("Visualisation saved to '%s'", out_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Orchestrate the full log analysis workflow."""
    if not download_log_file():
        log.error("Analysis aborted: log file unavailable.")
        return

    log.info("Analysing log file: %s", LOCAL_LOG_FILE)

    log.info("Counting IP requests...")
    ip_counts = collect_ip_counts(LOCAL_LOG_FILE)
    high_request_ips = {ip for ip, count in ip_counts.items() if count > HIGH_REQUEST_THRESHOLD}
    log.info("Found %d IPs with >%d requests", len(high_request_ips), HIGH_REQUEST_THRESHOLD)

    log.info("Analysing log entries...")
    result = analyse_entries(LOCAL_LOG_FILE, high_request_ips)

    print_report(result)
    save_problematic_report(result)
    visualize_data(result)


if __name__ == "__main__":
    main()