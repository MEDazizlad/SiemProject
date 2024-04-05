import json
import logging
import os
import shutil
import subprocess

import psutil


def collect_network_traffic_all():
    """
    Captures network traffic on the currently active interface.

    Returns:
        list: List of captured traffic data (if successful), None otherwise.
    """
    active_interface = get_connected_interface()
    if not active_interface:
        logging.error("No active network interface found.")
        return None

    capture_file = 'network_traffic.etl'

    try:
        stop_trace_process = subprocess.run(['netsh', 'trace', 'stop'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            timeout=10)
        stop_trace_process.check_returncode()  # Check if the command executed successfully
    except subprocess.CalledProcessError as e:
        # Check if there's an error message
        error_message = e.stderr.decode('utf-8').strip() if e.stderr else None
        if error_message and 'A tracing session is not in progress' not in error_message:
            logging.error(f"Error stopping existing tracing session: {error_message}")
            return None
        elif not error_message:
            logging.error("Error stopping existing tracing session: No error message returned.")
            return None
    except subprocess.TimeoutExpired:
        logging.error("Timeout expired while stopping existing tracing session.")
        return None

    try:
        if not os.path.exists(capture_file):
            open(capture_file, 'w').close()  # Create an empty file

        subprocess.run(['netsh', 'trace', 'start', 'persistent=yes', 'capture=yes',
                        f'traceFile={capture_file}'], check=True)
        subprocess.run(['netsh', 'trace', 'stop'], check=True)  # Stop the trace after capturing

        # Check if captured file is empty
        if os.path.getsize(capture_file) == 0:
            logging.warning("Captured network traffic file is empty. No traffic detected during capture.")
            os.remove(capture_file)  # Remove the capture file after parsing
            return []
        # Convert captured traffic data to list
        traffic_data = parse_network_traffic(capture_file)

        os.remove(capture_file)  # Remove the capture file after parsing

        return traffic_data
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode('utf-8') if e.output else str(e)
        logging.error(f"Error capturing network traffic: {error_output}")
        return None
    except Exception as e:
        logging.error(f"Error capturing network traffic: {e}")
        return None


def parse_network_traffic(capture_file):
    """
    Parse captured network traffic data from an ETL file.

    Args:
        capture_file (str): Path to the captured traffic file.

    Returns:
        list: List of captured traffic data (if successful), None otherwise.
    """
    try:
        # This is a placeholder for actual parsing logic
        # You need to implement proper parsing based on the capture file format (ETL)
        # Replace this with your actual parsing logic
        with open(capture_file, 'rb') as f:
            # Placeholder: Read the data and parse accordingly
            # Example: traffic_data = parse_etl_data(f)
            # Here, parse_etl_data is a function you implement to parse ETL data
            # This will depend on the actual format of the ETL data
            # For the sake of demonstration, let's assume we're reading the data as JSON
            traffic_data = json.load(f)
        return traffic_data
    except Exception as e:
        logging.error(f"Error parsing network traffic data: {e}")
        return None


def get_connected_interface():
    """
    Detects the currently active network interface (WiFi or Ethernet).

    Returns:
        str: Name of the active network interface (e.g., 'eth0', 'Wi-Fi').
             Returns None if no active interface is found.
    """
    connections = psutil.net_connections()
    for conn in connections:
        if conn.status == psutil.CONN_ESTABLISHED:
            return conn.laddr[0]
    return None


def monitor_file_system_events(directory):
    """
    Monitors a directory for changes and returns a list of dictionaries containing file data.

    Args:
        directory (str): Path to the directory to monitor.

    Returns:
        list: List of dictionaries containing file data.
    """

    if not os.path.exists(directory):
        logging.error(f"Directory '{directory}' does not exist.")
        return []

    # Use a more robust method to track changes, like inotify on Linux or filesystem monitoring APIs
    # This is a simplified example
    file_data = []
    for f in os.listdir(directory):
        filepath = os.path.join(directory, f)
        if os.path.isfile(filepath):
            file_data.append({
                'filepath': filepath,
                'filename': f,
                'filesize': os.path.getsize(filepath),
                'creation_time': os.path.getctime(filepath)
            })
    return file_data


def collect_system_logs(source_dir, destination_dir):
    """
    Collects system logs from a specified source directory and copies them to a destination directory.

    Args:
        source_dir (str): Path to the directory containing system logs.
        destination_dir (str): Path to the directory where logs will be copied.

    Returns:
        list: List of dictionaries containing log data (if successful), empty list otherwise.
    """

    if not os.path.exists(source_dir):
        logging.error(f"Source directory '{source_dir}' does not exist.")
        return []

    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)  # Create destination directory if it doesn't exist

    try:
        shutil.copytree(source_dir, destination_dir, dirs_exist_ok=True)  # Handle existing directory
        log_entries = []
        for root, _, filenames in os.walk(destination_dir):
            for filename in filenames:
                log_data = {
                    'filepath': os.path.join(root, filename),
                    # Parse log content for relevant data points suitable for dashboards (example)
                    'timestamp': os.path.getmtime(os.path.join(root, filename)),  # Extract timestamp
                    'log_level': 'INFO'  # Placeholder, extract from actual log content if possible
                }
                log_entries.append(log_data)
        return log_entries
    except Exception as e:
        logging.error(f"Error copying logs: {e}")
        return []


"""
    # Define system-specific log locations (adjust for your OS)
    system_log_source = os.path.join(os.environ['SystemRoot'], 'System32', 'winevt',
                                     'Logs') if os.name == 'nt' else '/var/log'
    system_logs_destination = 'logs/system_logs'
    documents_dir = os.path.expanduser('~\\Documents')
'System Logs': collect_system_logs(system_log_source, system_logs_destination),
                      'File System Events': monitor_file_system_events(documents_dir),
"""
"""
@app.route('/system-logs')
def system_logs():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'System Logs', 'data': latest_data['System Logs']})
    else:
        return 'Data is being collected...'

@app.route('/file-system')
def file_system():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'File System Events', 'data': latest_data['File System Events']})
    else:
        return 'Data is being collected...'


"""
