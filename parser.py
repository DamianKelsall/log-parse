import re
import os
import csv
import argparse
import configparser
from datetime import datetime
from collections import Counter

def load_patterns(config_file="patterns.ini"):
    config = configparser.ConfigParser()
    config.read(config_file)
    patterns = {}

    if "Patterns" in config:
        for name, regex in config["Patterns"].items():
            try:
                patterns[name] = re.compile(regex)
            except re.error:
                print(f"Invalid regex for pattern '{name}' — skipping.")
    return patterns

def parse_log(file_path, patterns, start_date=None, end_date=None):
    suspicious = []
    stats = Counter()

    start = datetime.strptime(start_date, "%Y-%m-%d") if start_date else None
    end = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None
    if end:
        end = end.replace(hour=23, minute=59, second=59)

    with open(file_path, 'r') as file:
        for line_num, line in enumerate(file, 1):
            for name, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    timestamp_str = match.group(1)
                    try:
                        log_date = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
                    except ValueError:
                        continue

                    if start and log_date < start:
                        continue
                    if end and log_date > end:
                        continue

                    if name == "failed_login":
                        user, ip = match.group(2), match.group(3)
                        msg = f"{line_num}: {log_date.date()} - Failed login by {user} from {ip}"
                        stats[f"failed_login:{user}"] += 1
                    elif name == "invalid_user":
                        user, ip = match.group(2), match.group(3)
                        msg = f"{line_num}: {log_date.date()} - Invalid user {user} from {ip}"
                        stats[f"invalid_user:{user}"] += 1
                    elif name == "sudo_fail":
                        user = match.group(2)
                        msg = f"{line_num}: {log_date.date()} - Sudo authentication failure for {user}"
                        stats[f"sudo_fail:{user}"] += 1
                    else:
                        msg = f"{line_num}: {log_date.date()} - Matched {name}"
                        stats[name] += 1

                    suspicious.append({
                        "line": line_num,
                        "date": log_date.strftime("%Y-%m-%d"),
                        "type": name,
                        "user": match.group(2) if len(match.groups()) > 1 else "",
                        "ip": match.group(3) if len(match.groups()) > 2 else "",
                        "message": msg
                    })
                    break

    return suspicious, stats

def save_output(results, stats, out_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("output", exist_ok=True)
    out_path = f"output/{out_file}_{timestamp}.csv"

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["line", "date", "type", "user", "ip", "message"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ Results saved to: {out_path}\n")
    print("📊 Summary:")
    for key, count in stats.items():
        print(f"{key}: {count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced log parser with CSV output and pattern config")
    parser.add_argument("logfile", help="Path to a log file or folder")
    parser.add_argument("--start", help="Start date (YYYY-MM-DD)", default=None)
    parser.add_argument("--end", help="End date (YYYY-MM-DD)", default=None)
    parser.add_argument("--output", default="suspicious", help="Output file name prefix")
    parser.add_argument("--config", default="patterns.ini", help="Path to pattern config file")

    args = parser.parse_args()
    patterns = load_patterns(args.config)

    results = []
    stats = Counter()

    if os.path.isdir(args.logfile):
        for root, _, files in os.walk(args.logfile):
            for name in files:
                if name.endswith(".log"):
                    filepath = os.path.join(root, name)
                    r, s = parse_log(filepath, patterns, args.start, args.end)
                    results.extend(r)
                    stats.update(s)
    else:
        results, stats = parse_log(args.logfile, patterns, args.start, args.end)

    if results:
        print(f"\nFound {len(results)} suspicious entries:\n")
        for entry in results:
            print(entry["message"])
        save_output(results, stats, args.output)
    else:
        print("No suspicious activity found.")

