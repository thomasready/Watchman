# streamlit_app.py

import streamlit as st
import os
import pandas as pd
import sqlite3
import io
import base64

# Import Watchman's core modules
from src.parsers.linux_auth_parser import parse_linux_auth_log_line
from src.database import initialize_db, insert_linux_auth_log, get_all_linux_auth_logs, update_log_status_and_notes
from src.detection_rules.linux_auth_rules import run_linux_auth_detection_rules
from src.utils import detect_log_type


# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="Watchman - Linux Log Analyzer",
    page_icon="🕵️‍♂️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Global Data Storage (Streamlit's session state for persistent data across reruns) ---
if 'triggered_alerts_display' not in st.session_state:
    st.session_state.triggered_alerts_display = []
if 'total_processed_logs_overall' not in st.session_state:
    st.session_state.total_processed_logs_overall = 0
if 'total_alerts_overall' not in st.session_state:
    st.session_state.total_alerts_overall = 0

# Session state for brute-force trackers
if 'apache_failed_attempts_tracker' not in st.session_state: 
    st.session_state.apache_failed_attempts_tracker = {}
if 'ssh_failed_attempts_tracker' not in st.session_state:
    st.session_state.ssh_failed_attempts_tracker = {}

# Session state to store IDs of log lines that triggered alerts
if 'alerted_log_ids' not in st.session_state:
    st.session_state.alerted_log_ids = set()


# --- Define the absolute path to the database file ---
DATABASE_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'watchman.db')

# --- Initialize the database right when the app starts ---
initialize_db(DATABASE_FILE_PATH) 


# --- Helper function for log ingestion (for text area) ---
def ingest_log_data_from_string(log_string):
    """
    Reads log data from a raw string input (from text area).
    Yields each raw log line.
    """
    for line in io.StringIO(log_string):
        yield line.strip()

# --- Callback function for updating alert status/notes (UPDATED ARGS) ---
def update_alert_status_callback(log_id_to_update, new_status_value, new_notes_value): # NEW ARGS
    update_log_status_and_notes(log_id_to_update, new_status_value, new_notes_value, DATABASE_FILE_PATH)
    st.success(f"Log ID {log_id_to_update} status updated to '{new_status_value}' and notes saved.")
    st.rerun() 

# --- Core Log Processing Function (Triggers on button click) ---
def process_logs_and_display(log_string_input): 
    st.write("### Initiating Linux Log Analysis...")
    
    # Clear alerts and counts from previous runs for a fresh display
    st.session_state.triggered_alerts_display = [] 
    st.session_state.total_processed_logs_overall = 0
    st.session_state.total_alerts_overall = 0
    
    # Clear rule trackers in session state for a fresh run
    st.session_state.apache_failed_attempts_tracker = {} 
    st.session_state.ssh_failed_attempts_tracker = {}
    
    # Clear alerted log IDs for a fresh run
    st.session_state.alerted_log_ids = set() 
        
    # --- Clear existing data in the DB tables ---
    conn = sqlite3.connect(DATABASE_FILE_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM linux_auth_logs') 
    conn.commit()
    conn.close()
    
    log_count = 0
    current_run_alerts = [] 

    # --- Detect Log Type ---
    log_lines_list = [line.strip() for line in io.StringIO(log_string_input) if line.strip()] 
    
    if not log_lines_list: 
        st.warning("Please paste Linux log lines into the text area for analysis.") 
        st.stop() 

    detected_type = detect_log_type(log_lines_list) 

    if detected_type == 'unknown': 
        st.error("Could not detect log type as Linux Auth. Please ensure valid Linux authentication logs are pasted.") 
        st.session_state.total_processed_logs_overall = len(log_lines_list)
        st.info(f"Processed {len(log_lines_list)} lines, but type is unknown. No alerts or parsing performed.")
        st.rerun() 
        st.stop()
    elif detected_type == 'apache': 
         st.error("Detected Apache logs. This Watchman instance is configured for Linux Auth logs only. Please paste Linux logs.")
         st.session_state.total_processed_logs_overall = len(log_lines_list)
         st.info(f"Ignored {len(log_lines_list)} lines: Apache detected but not supported.")
         st.rerun()
         st.stop()


    st.markdown(f"##### Detected Log Type: **Linux Auth Logs**") 
    
    # --- Process Logs based on detected type (now only Linux) ---
    log_iterator = ingest_log_data_from_string(log_string_input) 
    
    parser_func = parse_linux_auth_log_line
    insert_func = insert_linux_auth_log
    rules_func = run_linux_auth_detection_rules
    tracker_func = st.session_state.ssh_failed_attempts_tracker 

    with st.spinner(f"Analyzing Linux auth logs..."): 
        for raw_log_line in log_iterator:
            parsed_data = parser_func(raw_log_line)
            if parsed_data:
                # Store the log, then get its ID
                insert_func(parsed_data, raw_log_line, DATABASE_FILE_PATH)
                
                conn_temp = sqlite3.connect(DATABASE_FILE_PATH)
                last_row_id = conn_temp.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn_temp.close()

                triggered_alerts = rules_func(parsed_data, tracker_func) 
                
                if triggered_alerts:
                    for alert in triggered_alerts:
                        alert['log_id'] = last_row_id 
                        alert['raw_log_line'] = raw_log_line 
                        current_run_alerts.append(alert)
                        st.session_state.alerted_log_ids.add(last_row_id) 
                log_count += 1
    st.info(f"Processed {log_count} Linux authentication log lines.")


    st.session_state.total_processed_logs_overall = log_count
    st.session_state.total_alerts_overall = len(current_run_alerts)
    st.session_state.triggered_alerts_display.extend(current_run_alerts)


    st.success("Finished all log processing!")
    st.rerun()

# --- Streamlit UI Layout ---

st.title("🛡️ Watchman Dashboard")
st.markdown("Your personal **Linux authentication log** analyzer and threat detection system.")

# --- Centralized Text Input ---
st.header("Paste Your Linux Log Lines Here") 
pasted_logs_input = st.text_area(
    "Paste raw **Linux authentication log** lines for analysis. Watchman will detect if they are valid.", 
    height=300, 
    help="Paste raw Linux authentication log lines (e.g., from /var/log/auth.log or syslog). Max 500 KB."
)

st.button("Analyze Logs", on_click=process_logs_and_display, args=(pasted_logs_input,))


# --- Main Content Area ---

st.header("Analysis Summary")

col1, col2 = st.columns(2)
with col1:
    st.metric(label="Total Processed Linux Logs", value=st.session_state.total_processed_logs_overall)
with col2:
    st.metric(label="Total Alerts Found", value=st.session_state.total_alerts_overall)


st.header("Triggered Alerts")
# --- Severity Highlighting & Icon ---
def get_severity_icon(severity):
    if severity == 'Critical':
        return "🚨"
    elif severity == 'High':
        return "⚠️"
    elif severity == 'Medium':
        return "🟡"
    elif severity == 'Low':
        return "🟢"
    return ""

def highlight_severity(row):
    color = ''
    if row['severity'] == 'Critical':
        color = 'background-color: #ffcccc; color: #cc0000; font-weight: bold;'
    elif row['severity'] == 'High':
        color = 'background-color: #ffe0b3; color: #333333; font-weight: bold;'
    elif row['severity'] == 'Medium':
        color = 'background-color: #ffffcc; color: #333333;'
    elif row['severity'] == 'Low':
        color = 'background-color: #e6ffe6; color: #006600;'
    return [color] * len(row)

if st.session_state.triggered_alerts_display:
    alerts_df = pd.DataFrame(st.session_state.triggered_alerts_display)
    
    alerts_df['Icon'] = alerts_df['severity'].apply(get_severity_icon)
    alerts_df_display = alerts_df[['Icon', 'rule_id', 'severity', 'description', 'details', 'log_id', 'raw_log_line']] # Included raw_log_line and details

    st.dataframe(alerts_df_display.style.apply(highlight_severity, axis=1), use_container_width=True, hide_index=True)
    
    # --- Alert Management UI (Expander for each alert) ---
    st.markdown("---")
    st.subheader("Manage Alerts & View Full Details")
    for i, alert in alerts_df_display.iterrows():
        expander_key = f"alert_details_{i}_{alert['log_id']}"
        
        # Fetch current status/notes for this log_id from DB
        conn_temp = sqlite3.connect(DATABASE_FILE_PATH)
        cursor_temp = conn_temp.cursor()
        cursor_temp.execute("SELECT status, analyst_notes FROM linux_auth_logs WHERE id = ?", (alert['log_id'],))
        row_data = cursor_temp.fetchone() 
        conn_temp.close()
        
        current_status = row_data[0] if row_data else 'Open'
        current_notes = row_data[1] if row_data else ''
        raw_log_line_for_display = alert['raw_log_line'] # Fetch directly from alert object


        with st.expander(f"{alert['Icon']} **Alert ID: {alert['log_id']}** - {alert['description'][:70]}... (Status: {current_status})"):
            st.write(f"**Rule ID:** {alert['rule_id']}")
            st.write(f"**Severity:** {alert['severity']}")
            st.write(f"**Description:** {alert['description']}")
            st.write(f"**Details:** {alert['details']}") 

            st.text_area("Raw Log Line:", raw_log_line_for_display, height=100, key=f"raw_log_{i}_{alert['log_id']}")


            st.markdown("---")
            st.write(f"**Analyst Actions for Log ID: {alert['log_id']}**")
            
            # --- Alert Status Dropdown ---
            new_status_select = st.selectbox(
                "Update Status:",
                ['Open', 'Investigating', 'Resolved', 'False Positive', 'Escalate'], # ADDED 'Escalate'
                index=['Open', 'Investigating', 'Resolved', 'False Positive', 'Escalate'].index(current_status),
                key=f'status_select_{i}_{alert["log_id"]}' 
            )
            
            # --- Analyst Notes Text Area ---
            new_notes_text = st.text_area(
                "Analyst Notes:",
                value=current_notes,
                height=100,
                key=f'notes_text_{i}_{alert["log_id"]}' 
            )
            
            # --- Save Button ---
            st.button(
                "Save Status & Notes",
                on_click=update_alert_status_callback,
                args=(alert['log_id'], new_status_select, new_notes_text), # NEW: Pass values directly
                key=f'save_button_{i}_{alert["log_id"]}' 
            )
    
    # --- Download Alerts Button ---
    csv_alerts = alerts_df_display.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Triggered Alerts as CSV",
        data=csv_alerts,
        file_name="watchman_alerts.csv",
        mime="text/csv",
        key="download_alerts_csv"
    )
else:
    st.info("No alerts triggered. Paste Linux logs above and click 'Analyze Logs'.")


st.header("Raw Log Data (from Database)")

# --- Highlighting for Raw Logs (Using the updated status from DB) ---
def highlight_alerted_logs_with_status(row):
    conn_inner = sqlite3.connect(DATABASE_FILE_PATH)
    cursor_inner = conn_inner.cursor()
    
    cursor_inner.execute("SELECT status FROM linux_auth_logs WHERE id = ?", (int(row['id']),)) 
    status_from_db = cursor_inner.fetchone()
    conn_inner.close()

    status = status_from_db[0] if status_from_db else 'Open' 

    if row['id'] in st.session_state.alerted_log_ids: 
        if status == 'Resolved':
            return ['background-color: #e6ffe6; color: #006600;'] * len(row) 
        elif status == 'False Positive':
            return ['background-color: #fffacd; color: #cc6600;'] * len(row) 
        elif status == 'Investigating':
            return ['background-color: #ffffcc; color: #333333;'] * len(row) 
        elif status == 'Escalate': # NEW: Style for Escalate
            return ['background-color: #ffcc99; color: #cc6600; font-weight: bold;'] * len(row) # Light orange-red, dark orange text
        else: # Open or Critical/High
            return ['background-color: #ffcccc; color: #cc0000; font-weight: bold;'] * len(row) 
    return [''] * len(row) # No special styling for non-alerted logs

all_linux_auth_logs_from_db = get_all_linux_auth_logs(DATABASE_FILE_PATH) 

if all_linux_auth_logs_from_db:
    selected_logs_df = pd.DataFrame(all_linux_auth_logs_from_db)
    total_logs_in_db = len(all_linux_auth_logs_from_db)

    st.write("Displaying **Linux Auth Logs** from last analysis:") 
    search_query = st.text_input(f"Search Linux Logs (e.g., IP, user, message)", key=f"log_search_display") 
    if search_query:
        filtered_logs_df = selected_logs_df[
            selected_logs_df.apply(
                lambda row: row.astype(str).str.contains(search_query, case=False, na=False).any(),
                axis=1
            )
        ]
        st.dataframe(filtered_logs_df.style.apply(highlight_alerted_logs_with_status, axis=1), use_container_width=True) 
        st.markdown(f"Displaying {len(filtered_logs_df)} / {total_logs_in_db} logs matching your search.")
    else:
        st.dataframe(selected_logs_df.style.apply(highlight_alerted_logs_with_status, axis=1), use_container_width=True) 
        st.markdown(f"Displaying all {total_logs_in_db} Linux Auth Logs from the database.")
    
    # --- Download Raw Logs Button ---
    csv_raw_logs = selected_logs_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Raw Logs as CSV",
        data=csv_raw_logs,
        file_name="watchman_raw_logs.csv",
        mime="text/csv",
        key="download_raw_logs_csv"
    )
else:
    st.info("No Linux authentication logs found in the database. Paste logs above and click 'Analyze Logs'.")


st.markdown("---")
st.caption("Watchman: Your open-source security log analyzer.")