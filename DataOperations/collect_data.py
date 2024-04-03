import datetime
import json
import logging
import os
import platform
import shutil
import subprocess

import psutil
import win32evtlog
import win32evtlogutil

# Configure logging for informative messages and error handling
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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


def collect_system_information():
    """
    Collects various system data.

    Returns:
        dict: Dictionary containing system data.
    """
    try:
        disk_usage = psutil.disk_usage('/')
        system_platform = platform.system()
        return {
            'System Data': {'OS': system_platform, 'Platform': platform.platform()},
            'System Metrics': {
                'CPU Usage': psutil.cpu_percent(),
                'Memory Usage': psutil.virtual_memory().percent
            },
            'Disk Usage': {
                'Total Disk Space': disk_usage.total,
                'Used Disk Space': disk_usage.used,
                'Free Disk Space': disk_usage.free
            },
            'Network Interfaces': {
                'Active Interface': get_connected_interface()
            },
            'Processes': {
                'Running Processes': len(psutil.pids())
            },
            'Users': {
                'Users Logged In': len(psutil.users())
            }
        }
    except Exception as e:
        # Handle exceptions gracefully
        print(f"Error collecting system information: {e}")
        return {}


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


def collect_network_traffic():
    """
    Collects network traffic data.

    Returns:
        dict: Dictionary containing network traffic statistics.
    """
    network_stats = psutil.net_io_counters()
    traffic_data = collect_network_traffic_all()
    return {
        'Traffic Data': traffic_data or {},
        'Traffic Metrics': {
            'bytes_sent': network_stats.bytes_sent,
            'bytes_received': network_stats.bytes_recv
        }
    }


def collect_security_events(event_log_source):
    """
    Collects security events from the specified Windows Event Viewer log for the current day.

    Args:
        event_log_source (str): Source name of the security event log (e.g., "Security").

    Returns:
        list: A list containing two sublists: [normal_events, potential_threats].
    """
    normal_events = []
    potential_threats = []

    try:
        handle = win32evtlog.OpenEventLog(None, event_log_source)
        while True:
            try:
                event_records = win32evtlog.ReadEventLog(handle,
                                                         win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                                                         0)
                if not event_records:
                    break
                for event in event_records:
                    # Get the start and end timestamps for the current day
                    today = datetime.datetime.now().date()
                    start_time = datetime.datetime.combine(today, datetime.time.min)
                    end_time = datetime.datetime.combine(today, datetime.time.max)
                    if start_time <= event.TimeGenerated <= end_time:
                        event_data = {
                            'event_id': event.EventID,
                            'source': event.SourceName,
                            'time_generated': event.TimeGenerated,
                            'message': win32evtlogutil.SafeFormatMessage(event, event_log_source),
                            'category': event.EventCategory,
                            'event_type': event.EventType,
                            'computer_name': event.ComputerName,
                            'event_data': event.StringInserts  # Example of event data, may vary for different events
                        }
                        # Check if the event message contains any suspicious keywords
                        if any(keyword in event_data['message'].lower() for keyword in
                               ["unauthorized access", "malicious activity", "failed login attempts"]):
                            potential_threats.append(event_data)
                        else:
                            normal_events.append(event_data)

            except Exception as e:  # Catch any exceptions during reading
                logging.error(f"Error reading security events: {e}")
                continue  # Move on to the next iteration

    finally:
        win32evtlog.CloseEventLog(handle)  # Ensure handle is closed even on errors

    return {'Normal Events': normal_events, 'Potential Threats': potential_threats,
            'Total Events': len(normal_events) + len(potential_threats)}


def collect_data():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Define system-specific log locations (adjust for your OS)
    system_log_source = os.path.join(os.environ['SystemRoot'], 'System32', 'winevt',
                                     'Logs') if os.name == 'nt' else '/var/log'
    system_logs_destination = 'logs/system_logs'
    documents_dir = os.path.expanduser('~\\Documents')

    # Collect data
    collected_data = {'System Logs': collect_system_logs(system_log_source, system_logs_destination),
                      'File System Events': monitor_file_system_events(documents_dir),
                      'System Information': collect_system_information(),
                      'Network Traffic': collect_network_traffic(),
                      'Security Events': collect_security_events('Security'),
                      }

    return collected_data
