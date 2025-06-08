# src/utils.py
import re
from datetime import datetime

def detect_log_type(log_lines):
    """
    Analyzes the first few log lines to determine if they are Linux Auth Logs.
    Returns 'linux_auth' or 'unknown'.
    """
    sample_lines = log_lines[:10] 

    linux_auth_keywords = [
        re.compile(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(sshd|sudo|login):'),
        re.compile(r'Accepted password for'),
        re.compile(r'Failed password for'),
        re.compile(r'session opened for user')
    ]

    linux_auth_score = 0

    for line in sample_lines:
        for pattern in linux_auth_keywords:
            if pattern.search(line):
                linux_auth_score += 1
    
    if linux_auth_score > 0: # If any Linux auth patterns are found
        return 'linux_auth'
    else:
        return 'unknown'

# Example usage for testing this module directly
if __name__ == "__main__":
    linux_sample = [
        'Jun  7 10:01:00 watchman sshd[1234]: Accepted password for tomready from 192.168.1.50 port 54321 ssh2',
        'Jun  7 10:01:15 watchman sudo: pam_unix(sudo:auth): authentication failure;'
    ]
    apache_sample_now_unknown = [ # These will now be 'unknown'
        '192.168.1.10 - - [07/Jun/2025:10:00:01 +1200] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.5 - - [07/Jun/2025:10:00:05 +1200] "POST /login.php HTTP/1.1" 401 250 "http://example.com/login.php" "Mozilla/5.0"'
    ]
    unknown_sample = [
        'This is just some random text.',
        'Another line here that is not a log.'
    ]

    print(f"Linux sample detected as: {detect_log_type(linux_sample)}")
    print(f"Apache sample detected as: {detect_log_type(apache_sample_now_unknown)}")
    print(f"Unknown sample detected as: {detect_log_type(unknown_sample)}")