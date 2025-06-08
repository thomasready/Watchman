# src/database.py
import sqlite3
import json
import os
import datetime

def initialize_db(db_path):
    """
    Initializes the SQLite database and creates the necessary tables.
    (Now only creates linux_auth_logs table with status and notes)
    """
    data_dir = os.path.dirname(db_path)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Only create table for Linux authentication logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS linux_auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            hostname TEXT,
            process_info TEXT,
            message TEXT NOT NULL,
            user TEXT,
            ip TEXT,
            raw_log_line TEXT NOT NULL,
            parsed_at TEXT NOT NULL,
            status TEXT DEFAULT 'Open',       -- NEW: Status of the alert related to this log
            analyst_notes TEXT DEFAULT ''     -- NEW: Notes by analyst
        )
    ''')

    conn.commit()
    conn.close() 
    print(f"Database initialized at {db_path}")


def insert_linux_auth_log(log_data, raw_log_line, db_path, status='Open', analyst_notes=''): # NEW ARG: status, analyst_notes
    """
    Inserts a parsed Linux auth log entry into the database.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    timestamp_str = log_data.get('timestamp').isoformat() if log_data.get('timestamp') else None
    hostname = log_data.get('hostname')
    process_info = log_data.get('process_info')
    message = log_data.get('message')
    user = log_data.get('user')
    ip = log_data.get('ip')
    
    parsed_at = datetime.datetime.now().isoformat()

    try:
        cursor.execute('''
            INSERT INTO linux_auth_logs (timestamp, hostname, process_info, message, user, ip, raw_log_line, parsed_at, status, analyst_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp_str, hostname, process_info, message, user, ip, raw_log_line, parsed_at, status, analyst_notes))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during insert: {e}")
        conn.rollback() 
    finally:
        conn.close()

def update_log_status_and_notes(log_id, new_status, new_notes, db_path): # NEW FUNCTION
    """
    Updates the status and notes for a specific log entry by its ID.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE linux_auth_logs
            SET status = ?, analyst_notes = ?
            WHERE id = ?
        ''', (new_status, new_notes, log_id))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error during update: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_all_linux_auth_logs(db_path):
    """
    Retrieves all stored Linux auth log entries from the database.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row 
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM linux_auth_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Example usage for testing this module directly
if __name__ == "__main__":
    test_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'test_watchman_linux_only_status.db')
    initialize_db(test_db_path)
    print(f"Linux-only test database initialized at {test_db_path}")
    # You could add a test insertion and update here if needed
    # For example:
    # log_data = {'timestamp': datetime.datetime.now(), 'hostname': 'test', 'process_info': 'test', 'message': 'test', 'user': 'test', 'ip': '1.1.1.1'}
    # insert_linux_auth_log(log_data, 'raw_test_line', test_db_path)
    # print("Inserted test log.")
    # logs = get_all_linux_auth_logs(test_db_path)
    # print(f"Current logs: {logs}")
    # if logs:
    #     update_log_status_and_notes(logs[0]['id'], 'Resolved', 'Resolved for testing', test_db_path)
    #     print(f"Updated log: {get_all_linux_auth_logs(test_db_path)[0]}")