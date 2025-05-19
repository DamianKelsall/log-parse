import re
import argparse
from datetime import datetime

def parse_log(file_path, keyword):
    suspicious = []

    with open(file_path, 'r') as file:
        for line_num, line in enumerate(file, 1):
            if keyword.lower() in line.lower():
                suspicious.append(f"{line_num}: {line.strip()}")

    return suspicious

def save_output(results, out_file):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"output/{out_file}_{timestamp}.txt", "w") as f:
        for entry in results:
            f.write(entry + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log file keyword parser")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("keyword", help="Keyword to search for (e.g. failed)")
    parser.add_argument("--output", default="suspicious", help="Output file name prefix")

    args = parser.parse_args()
    results = parse_log(args.logfile, args.keyword)

    if results:
        print(f"Found {len(results)} suspicious entries:")
        for entry in results:
            print(entry)
        save_output(results, args.output)
    else:
        print("No suspicious activity found.")

