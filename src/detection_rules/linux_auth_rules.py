# src/detection_rules/linux_auth_rules.py
import re
from datetime import datetime, timedelta
import datetime as dt

def detect_ssh_brute_force_auth(log_data, ssh_failed_attempts_tracker, threshold=3, time_window_seconds=30):
    """
    Detects potential SSH brute-force attacks from auth.log.
    'ssh_failed_attempts_tracker' is a dictionary to track attempts.
    """
    message = log_data.get('message', '').lower()
    ip = log_data.get('ip')
    timestamp = log_data.get('timestamp')

    if ip and timestamp and "failed password for" in message and "sshd" in log_data.get('process_info', '').lower():
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                timestamp = None

        if not isinstance(timestamp, datetime):
            return None

        if ip not in ssh_failed_attempts_tracker:
            ssh_failed_attempts_tracker[ip] = {'timestamps': [], 'count': 0}

        current_time_window_start = timestamp - timedelta(seconds=time_window_seconds)
        ssh_failed_attempts_tracker[ip]['timestamps'] = [
            ts for ts in ssh_failed_attempts_tracker[ip]['timestamps']
            if ts >= current_time_window_start
        ]
        if timestamp not in ssh_failed_attempts_tracker[ip]['timestamps']:
            ssh_failed_attempts_tracker[ip]['timestamps'].append(timestamp)
        
        ssh_failed_attempts_tracker[ip]['count'] = len(ssh_failed_attempts_tracker[ip]['timestamps'])

        if ssh_failed_attempts_tracker[ip]['count'] >= threshold:
            return {
                'rule_id': 'LINUX_SSH_BRUTE_FORCE_001',
                'severity': 'High',
                'description': f"Potential SSH brute-force from {ip} for user {log_data.get('user', 'unknown')}",
                'details': f"{ssh_failed_attempts_tracker[ip]['count']} failed attempts in {time_window_seconds}s."
            }
    return None

def detect_sudo_privilege_escalation(log_data):
    """
    Detects suspicious sudo activity.
    Flags if 'authentication failure' is recorded for sudo.
    """
    message = log_data.get('message', '').lower()
    if "sudo" in log_data.get('process_info', '').lower() and "authentication failure" in message:
        return {
            'rule_id': 'LINUX_SUDO_AUTH_FAIL_001',
            'severity': 'Medium',
            'description': f"Sudo authentication failure for user {log_data.get('user', 'unknown')}",
            'details': f"Message: {log_data.get('message')}"
        }
    return None

# --- NEW RULE: Root Login from Remote IP (CRITICAL) ---
def detect_root_remote_login(log_data):
    """
    Detects direct root login via SSH from a remote IP (not localhost or common internal ranges).
    """
    message = log_data.get('message', '').lower()
    ip = log_data.get('ip')
    user = log_data.get('user')

    # Fix: Ensure 'ip' is not None before calling .startswith()
    is_local_ip = (ip is not None and (ip == '127.0.0.1' or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.')))

    if user == 'root' and ip and not is_local_ip and \
       "accepted password for root" in message and "sshd" in log_data.get('process_info', '').lower():
        return {
            'rule_id': 'LINUX_ROOT_REMOTE_LOGIN_001',
            'severity': 'Critical',
            'description': f"Direct ROOT login via SSH from remote IP: {ip}",
            'details': f"Full message: {log_data.get('message')}"
        }
    return None

# --- NEW RULE: Failed Privileged User Login (HIGH) ---
def detect_failed_privileged_login(log_data):
    """
    Detects failed password attempts for highly privileged users (root, admin).
    """
    message = log_data.get('message', '').lower()
    user = log_data.get('user')

    if user in ['root', 'admin'] and "failed password for" in message and \
       "sshd" in log_data.get('process_info', '').lower():
        return {
            'rule_id': 'LINUX_FAILED_PRIV_USER_LOGIN_001',
            'severity': 'High',
            'description': f"Failed password attempt for privileged user '{user}' from IP: {log_data.get('ip')}",
            'details': f"Full message: {log_data.get('message')}"
        }
    return None

# --- NEW RULE: Sensitive Sudo Command Execution (MEDIUM) ---
SENSITIVE_SUDO_COMMANDS = re.compile(
    r'(cat /etc/shadow|cat /etc/passwd|rm -rf /|dd if=|mount /dev|chmod 777|chown root|usermod|groupadd|useradd|passwd)',
    re.IGNORECASE
)

def detect_sensitive_sudo_command(log_data):
    """
    Detects execution of sensitive commands via sudo.
    """
    message = log_data.get('message', '')
    process_info = log_data.get('process_info', '')

    if "sudo" in process_info.lower() and "COMMAND=" in message:
        command_match = re.search(r'COMMAND=(?P<command>.*)', message)
        if command_match:
            command = command_match.group('command').strip()
            if SENSITIVE_SUDO_COMMANDS.search(command):
                return {
                    'rule_id': 'LINUX_SUDO_SENSITIVE_CMD_001',
                    'severity': 'Medium',
                    'description': f"Sensitive command executed via sudo: '{command}' by user '{log_data.get('user')}'",
                    'details': f"Full message: {log_data.get('message')}"
                }
    return None

# --- NEW RULE: New Account Creation (LOW) ---
def detect_new_account_creation(log_data):
    """
    Detects new user account creation events.
    """
    message = log_data.get('message', '')
    process_info = log_data.get('process_info', '')
    
    if "sudo" in process_info.lower() and ("useradd" in message or "adduser" in message) and "COMMAND=" in message:
        user_match = re.search(r'(useradd|adduser)\s+(?P<username>\S+)', message)
        if user_match:
            username = user_match.group('username')
            return {
                'rule_id': 'LINUX_ACCOUNT_CREATION_001',
                'severity': 'Low',
                'description': f"New user account '{username}' created via sudo.",
                'details': f"Full message: {log_data.get('message')}"
            }
    return None


# --- Main function to run all Linux Auth detection rules ---
def run_linux_auth_detection_rules(log_data, ssh_failed_attempts_tracker):
    """
    Runs all defined Linux auth log detection rules against a single parsed log entry.
    Returns a list of alerts triggered, or an empty list if none.
    """
    alerts = []
    if not log_data:
        return alerts

    if isinstance(log_data.get('timestamp'), str):
        try:
            log_data['timestamp'] = datetime.fromisoformat(log_data['timestamp'])
        except ValueError:
             try:
                log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%Y-%m-%dT%H:%M:%S')
             except ValueError:
                log_data['timestamp'] = None
    
    # Run each detection rule
    if log_data.get('timestamp') is not None:
        alert_ssh_brute_force = detect_ssh_brute_force_auth(log_data, ssh_failed_attempts_tracker)
        if alert_ssh_brute_force:
            alerts.append(alert_ssh_brute_force)

    alert_sudo_fail = detect_sudo_privilege_escalation(log_data)
    if alert_sudo_fail:
        alerts.append(alert_sudo_fail)

    # NEW: Run new rules
    alert_root_remote_login = detect_root_remote_login(log_data)
    if alert_root_remote_login:
        alerts.append(alert_root_remote_login)

    alert_failed_priv_login = detect_failed_privileged_login(log_data)
    if alert_failed_priv_login:
        alerts.append(alert_failed_priv_login)

    alert_sensitive_sudo = detect_sensitive_sudo_command(log_data)
    if alert_sensitive_sudo:
        alerts.append(alert_sensitive_sudo)

    alert_new_account = detect_new_account_creation(log_data)
    if alert_new_account:
        alerts.append(alert_new_account)

    return alerts

# Example usage for testing this module directly
if __name__ == "__main__":
    test_ssh_failed_attempts = {} # Local tracker for test
    print("--- Testing Linux Auth Detection Rules ---")
    
    current_test_time = datetime.now(datetime.timezone.utc)

    # Test cases for all 6 rules
    test_logs = [
        # SSH Brute-Force (HIGH)
        {'ip': '203.0.113.1', 'timestamp': current_test_time - timedelta(seconds=15), 'process_info': 'sshd[1235]', 'message': 'Failed password for testuser from 203.0.113.1 port 49000 ssh2', 'user': 'testuser'},
        {'ip': '203.0.113.1', 'timestamp': current_test_time - timedelta(seconds=10), 'process_info': 'sshd[1236]', 'message': 'Failed password for testuser from 203.0.113.1 port 49001 ssh2', 'user': 'testuser'},
        {'ip': '203.0.113.1', 'timestamp': current_test_time - timedelta(seconds=5), 'process_info': 'sshd[1237]', 'message': 'Failed password for testuser from 203.0.113.1 port 49002 ssh2', 'user': 'testuser'},

        # Sudo Auth Failure (MEDIUM)
        {'timestamp': current_test_time, 'hostname': 'watchman', 'process_info': 'sudo', 'message': 'pam_unix(sudo:auth): authentication failure; logname=devuser uid=1000 euid=0 tty=/dev/pts/0 ruser=devuser rhost=  user=devuser', 'user': 'devuser'},
        
        # Root Remote Login (CRITICAL) - Assume 203.0.113.4 is not local
        {'ip': '203.0.113.4', 'timestamp': current_test_time, 'process_info': 'sshd[1238]', 'message': 'Accepted password for root from 203.0.113.4 port 50000 ssh2', 'user': 'root'},

        # Failed Privileged User Login (HIGH)
        {'ip': '203.0.113.5', 'timestamp': current_test_time, 'process_info': 'sshd[1239]', 'message': 'Failed password for admin from 203.0.113.5 port 50001 ssh2', 'user': 'admin'},

        # Sensitive Sudo Command Execution (MEDIUM)
        {'timestamp': current_test_time, 'hostname': 'watchman', 'process_info': 'sudo', 'message': 'pam_unix(sudo:session): session opened for user userA by root(uid=0)COMMAND=/usr/bin/cat /etc/shadow', 'user': 'userA'},

        # New Account Creation (LOW)
        {'timestamp': current_test_time, 'hostname': 'watchman', 'process_info': 'sudo', 'message': 'pam_unix(sudo:session): session opened for user newuser by root(uid=0)COMMAND=/usr/sbin/adduser newuser', 'user': 'newuser'}
    ]

    for log in test_logs:
        alerts = run_linux_auth_detection_rules(log, test_ssh_failed_attempts)
        if alerts:
            for alert in alerts:
                print(f"  Alert! {alert['rule_id']} - {alert['severity']}: {alert['description']}")

    print("\n--- End of Detection Rules Test ---")