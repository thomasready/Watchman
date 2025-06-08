# app.py

import os
from src.parsers.apache_parser import parse_apache_log_line
from src.database import initialize_db, insert_apache_log, get_all_apache_logs
from src.detection_rules.apache_rules import run_apache_detection_rules # This assumes apache_rules.py is created and correct

def ingest_log_file(file_path):
    """
    Reads a log file line by line and yields each raw log line.
    Includes a check for file existence for better error messages.
    """
    if not os.path.exists(file_path):
        print(f"Error: Log file not found at {file_path}. Please check the path and filename.")
        return # Exit the generator if file not found

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line.strip() # .strip() removes leading/trailing whitespace, including newline characters
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")


# --- Main execution block ---
if __name__ == "__main__":
    initialize_db()
    sample_log_file_path = 'logs/apache_access.log' # Ensure this matches your log file name exactly

    print(f"--- Ingesting and Parsing logs from: {sample_log_file_path} ---")
    log_count = 0
    alert_count = 0

    for raw_log_line in ingest_log_file(sample_log_file_path):
        parsed_data = parse_apache_log_line(raw_log_line)
        if parsed_data:
            insert_apache_log(parsed_data, raw_log_line)
            # print(f"Stored: IP={parsed_data.get('ip')}, Path={parsed_data.get('path')}") # Optional: comment this out

            # Run Detection Rules
            triggered_alerts = run_apache_detection_rules(parsed_data)
            if triggered_alerts:
                for alert in triggered_alerts:
                    print(f"!!! ALERT !!! Rule: {alert['rule_id']}, Severity: {alert['severity']}, Desc: {alert['description']}")
                    alert_count += 1
            
            log_count += 1
        # else: # Optional: comment out this else block to reduce output
        #     print(f"Failed to parse line: {raw_log_line}")

    print(f"--- Finished ingesting and parsing {log_count} valid log lines and storing them. ---")
    print(f"--- Total Alerts Triggered: {alert_count} ---")
    
    # --- Displaying Stored Logs (from database) ---
    print("\n--- Displaying all stored Apache Logs (from database) ---")
    stored_logs = get_all_apache_logs()
    if stored_logs:
        for log in stored_logs:
            print(f"ID: {log['id']}, Time: {log['timestamp'][:19]}, IP: {log['ip']}, Path: {log['path']}, Status: {log['status_code']}")
    else:
        print("No Apache logs found in the database.")
    print("--- End of stored logs ---")