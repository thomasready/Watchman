# 🛡️ Watchman: Your Personal Linux Log Analyzer and Threat Detection System

Watchman is a powerful, interactive web application built with Python and Streamlit, designed to streamline the analysis of Linux authentication logs. It helps security analysts quickly identify potential threats such as SSH brute-force attacks, privileged user login failures, sensitive command executions via `sudo`, and new account creations.

## ✨ Key Features

* **Intelligent Log Ingestion:** Paste raw Linux authentication log lines directly into the web interface for instant analysis.
* **Automated Log Type Detection:** Watchman intelligently identifies Linux `auth.log` formats. It will warn if non-Linux logs are pasted, ensuring focused analysis.
* **Robust Rule-Based Threat Detection:** Employs a comprehensive set of 6 distinct detection rules across various severity levels:
    * **🚨 Critical:** Direct Root Login from Remote IP (`LINUX_ROOT_REMOTE_LOGIN_001`)
    * **⚠️ High:** SSH Brute-Force Attempts (`LINUX_SSH_BRUTE_FORCE_001`)
    * **⚠️ High:** Failed Privileged User Logins (`LINUX_FAILED_PRIV_USER_LOGIN_001`)
    * **🟡 Medium:** Sudo Authentication Failures (`LINUX_SUDO_AUTH_FAIL_001`)
    * **🟡 Medium:** Sensitive Sudo Command Execution (`LINUX_SUDO_SENSITIVE_CMD_001`)
    * **🟢 Low:** New Account Creation (`LINUX_ACCOUNT_CREATION_001`)
* **Interactive Web Dashboard (Streamlit):** Provides a user-friendly and responsive interface for analysis and alert management.
* **Visual Alerting:** Triggered alerts are displayed with distinct icons (🚨⚠️🟡🟢) and color-coded rows based on severity for immediate visual recognition.
* **Alert Management Workflow:**
    * **Status Tracking:** Mark alerts as 'Open', 'Investigating', 'Resolved', or 'False Positive' directly in the UI.
    * **Analyst Notes:** Add detailed investigation notes within the UI for each alert.
    * **Raw Log Line Integration:** View the exact raw log line associated with each triggered alert directly within the alert details.
* **Log Highlighting:** Alerted log lines in the "Raw Log Data" table are dynamically highlighted and color-coded based on their current status (e.g., red for open, green for resolved).
* **Search & Filter:** Easily search through displayed raw logs for specific keywords (IPs, users, messages).
* **Data Export:** Download triggered alerts or all raw processed logs as `.csv` files for reporting or external analysis.

## 🚀 How to Run Watchman (From Source)

This guide assumes you have a clean **Ubuntu ARM64 VM (e.g., using UTM on a MacBook)** with Python 3.10+ and Git installed.

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/thomasready/Watchman.git](https://github.com/thomasready/Watchman.git)
    cd Watchman
    ```
    (Replace `thomasready` with your actual GitHub username if different.)

2.  **Create and Activate a Python Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: If `requirements.txt` is missing or outdated, you can generate it in your active virtual environment by running `pip freeze > requirements.txt`)*

4.  **Initialize the Database:**
    * Ensure your `watchman.db` file is fresh with the correct schema. If you've run previous versions with different schemas, it's best to delete the old one first for a clean start:
        ```bash
        rm data/watchman.db # Only if it exists
        ```
    * The database will be initialized automatically when the Streamlit app starts.

5.  **Run the Streamlit Application:**
    ```bash
    streamlit run streamlit_app.py --server.port=8501 --server.address=0.0.0.0
    ```

6.  **Access Watchman:**
    * Copy the `Network URL` (e.g., `http://192.168.X.X:8501`) displayed in your terminal.
    * Paste this URL into your **MacBook's web browser**.

7.  **Analyze Logs:**
    * Paste your Linux authentication log lines (from `/var/log/auth.log` or similar) into the text area on the dashboard.
    * Click the **"Analyze Logs"** button.
    * Explore the analysis summary, triggered alerts, and raw log data. Experiment with updating alert statuses and adding notes!

## 🛠️ Technologies Used

* **Python:** Primary programming language (Python 3.10+).
* **Streamlit:** For building the interactive web User Interface.
* **SQLite3:** For local, file-based database storage of parsed logs and alert states.
* **Pandas:** For efficient data manipulation and tabular display in Streamlit.
* **`re` (Regular Expressions):** Extensively used for robust log parsing and rule-based threat detection.
* **`datetime`:** For precise timestamp handling and time-based alert logic.
* **Git / GitHub:** For version control, collaborative development, and project hosting.
* **Ubuntu ARM64 (VM):** The development and execution environment.
* **UTM:** Virtualization software used on Apple Silicon MacBooks.
* **Docker:** (Future: For containerization and simplified deployment).

## 💡 Future Enhancements

* Integrate with external threat intelligence sources (simulated or real APIs).
* Implement advanced data visualizations (e.g., alert trends over time, user activity heatmaps).
* Develop more sophisticated log parsing capabilities for diverse log formats (e.g., Windows Event Logs, firewall logs).
* Implement user authentication and multi-user support (for team environments).
* Add a "Case Management" system beyond simple status updates for full incident tracking.
* Deploy as a Docker container for even simpler distribution and scalability.

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.