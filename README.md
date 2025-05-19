# log-parse

A simple Python tool to scan log files for suspicious activity like failed logins, invalid users, and sudo failures. 

## What it does

- Scans `.log` files in a folder
- Looks for patterns like:
  - Failed SSH logins
  - Invalid usernames
  - Sudo authentication failures
- Filters by date
- Saves results to a CSV file
- Gives you a quick summary of what it found

## How to use it

1. Add your logs to a `logs/` folder
2. Define patterns in `patterns.ini` (some are already included)
3. Run the parser:

```bash
python3 parser.py logs/ --start 2025-05-01 --end 2025-05-20

## You’ll get output like:

Found 6 suspicious entries:
✅ Results saved to: output/suspicious_<timestamp>.csv

📊 Summary:
failed_login:admin: 1
invalid_user:root: 1
sudo_fail:damian: 1

## Example log line 

May 19 2025 12:30:42 server sshd[12345]: Failed password for admin from 192.168.1.10 port 22 ssh2
