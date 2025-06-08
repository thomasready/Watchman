# src/parsers/linux_auth_parser.py
import re
from datetime import datetime

# Regex pattern for common Linux auth.log entries (Syslog format)
# This is simplified; real auth.log can have many variations
LINUX_AUTH_LOG_PATTERN = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<process_info>.*?):\s+'
    r'(?P<message>.*)$'
)

def parse_linux_auth_log_line(log_line):
    """
    Parses a single Linux auth.log line and returns a dictionary of its components.
    Returns None if the line does not match the expected pattern.
    """
    match = LINUX_AUTH_LOG_PATTERN.match(log_line)
    if match:
        data = match.groupdict()

        # Construct a full timestamp (assuming current year, as logs usually don't have year)
        current_year = datetime.now().year
        timestamp_str_full = f"{data['month']} {data['day']} {current_year} {data['time']}"
        try:
            # Using a naive datetime, as auth.log typically doesn't have timezone offset
            data['timestamp'] = datetime.strptime(timestamp_str_full, '%b %d %Y %H:%M:%S')
        except ValueError:
            data['timestamp'] = None # Handle potential parsing errors for timestamp

        # Extract user/IP if present in message for common login/failure patterns
        user_match = re.search(r'for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', data['message'])
        if user_match:
            data['user'] = user_match.group('user')
            data['ip'] = user_match.group('ip')
        elif 'pam_unix(sudo:session): session opened for user' in data['message']:
            sudo_user_match = re.search(r'session opened for user (?P<user>\S+)', data['message'])
            if sudo_user_match:
                data['user'] = sudo_user_match.group('user')
        elif 'Accepted password for' in data['message']:
             accepted_user_match = re.search(r'Accepted password for (?P<user>\S+)', data['message'])
             if accepted_user_match:
                 data['user'] = accepted_user_match.group('user')
        elif 'Failed password for' in data['message']:
             failed_user_match = re.search(r'Failed password for (?P<user>\S+)', data['message'])
             if failed_user_match:
                 data['user'] = failed_user_match.group('user')

        data['log_type'] = 'linux_auth' # Add a type identifier

        return data
    return None

# Example usage for testing this module directly
if __name__ == "__main__":
    sample_line_success = 'Jun  7 10:01:00 watchman sshd[1234]: Accepted password for tomready from 192.168.1.50 port 54321 ssh2'
    sample_line_fail = 'Jun  7 10:01:15 watchman sshd[1235]: Failed password for invaliduser from 203.0.113.10 port 49000 ssh2'
    sample_line_sudo = 'Jun  7 10:01:30 watchman sudo: tomready : TTY=pts/0 ; PWD=/home/tomready ; USER=root ; COMMAND=/usr/bin/apt update'
    
    print("--- Testing Linux Auth Parser ---")
    
    parsed_success = parse_linux_auth_log_line(sample_line_success)
    print("\nParsed Success:")
    if parsed_success:
        for k, v in parsed_success.items(): print(f"  {k}: {v}")

    parsed_fail = parse_linux_auth_log_line(sample_line_fail)
    print("\nParsed Fail:")
    if parsed_fail:
        for k, v in parsed_fail.items(): print(f"  {k}: {v}")

    parsed_sudo = parse_linux_auth_log_line(sample_line_sudo)
    print("\nParsed Sudo:")
    if parsed_sudo:
        for k, v in parsed_sudo.items(): print(f"  {k}: {v}")

    print("\n--- End of Linux Auth Parser Test ---")