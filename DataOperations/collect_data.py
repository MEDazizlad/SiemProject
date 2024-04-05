import datetime
import logging
import platform
from collections import Counter

import psutil
import win32evtlog
import win32evtlogutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

# Configure logging for informative messages and error handling
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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
    Collects network traffic data for current network interfaces.

    Returns:
        dict: Dictionary containing network traffic statistics for current interface.
    """
    try:
        traffic_data = {}

        # Sniff network traffic for 5 seconds
        packets = sniff(timeout=5, iface=conf.iface)

        # Process sniffed packets and collect statistics
        traffic_data['Total Packets'] = len(packets)

        # Count distinct source and destination IPs
        source_ips = Counter()
        destination_ips = Counter()
        protocols = Counter()

        packet_details = []  # List to store packet details

        for packet in packets:
            if IP in packet:
                # Extract source and destination IP addresses
                if packet.haslayer(TCP):
                    protocol = "TCP"
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                else:
                    protocol = "Other"
                # Count protocol types
                protocols[protocol] += 1

                # Count distinct source and destination IPs
                source_ips[packet[IP].src] += 1
                destination_ips[packet[IP].dst] += 1

                # Add packet details to the list
                packet_details.append({
                    'timestamp': packet.time,  # Timestamp when the packet was captured
                    'source_ip': packet[IP].src,  # Source IP address
                    'destination_ip': packet[IP].dst,  # Destination IP address
                    'protocol': protocol,  # Network protocol name
                    'flags': packet.sprintf('%TCP.flags%') if packet.haslayer(TCP) else None,
                    # TCP flags (if applicable)
                })

        # Store the counts and packet details in traffic_data dictionary
        traffic_data['Distinct Source IPs'] = [{'ip': ip, 'count': count} for ip, count in source_ips.items()]
        traffic_data['Total Distinct Source IPs'] = len(traffic_data['Distinct Source IPs'])
        traffic_data['Distinct Destination IPs'] = [{'ip': ip, 'count': count} for ip, count in destination_ips.items()]
        traffic_data['Total Distinct Destination IPs'] = len(traffic_data['Distinct Destination IPs'])
        traffic_data['Distinct Protocols'] = [{'protocol': protocol, 'count': count} for protocol, count in
                                              protocols.items()]
        traffic_data['Packet Details'] = packet_details

        return traffic_data

    except Exception as e:
        logging.error(f"Error capturing network traffic: {e}")
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
        'Traffic Metrics': [{
            'bytes_sent': network_stats.bytes_sent,
            'bytes_received': network_stats.bytes_recv
        }]
    }


def collect_security_events(event_log_source):
    """
    Collects security events from the specified Windows Event Viewer log for the current day.

    Args:
        event_log_source (str): Source name of the security event log (e.g., "Security").

    Returns:
        dict: A dictionary containing normal events, potential threats, and the total number of events.
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
                    # Define event IDs that may indicate potential threats
                    threat_event_ids = {
                        4732, 4720, 4724, 4723, 4740, 4767, 4688, 4697, 4689, 4698,
                        4699, 4702, 4670, 4672, 4627, 7034, 7036, 7038, 7040, 1102,
                        1105, 104, 4624, 4625, 4768, 4776, 1100, 4658, 4663, 4673
                    }
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
                        if event.EventID in threat_event_ids:
                            potential_threats.append(event_data)
                        else:
                            normal_events.append(event_data)
            except Exception as e:  # Catch any exceptions during reading
                logging.error(f"Error reading security events: {e}")
                continue  # Move on to the next iteration

    finally:
        win32evtlog.CloseEventLog(handle)  # Ensure handle is closed even on errors

    return {
        # 'Normal Events': normal_events,
        'Potential Threats': potential_threats,
        'Total Threats': len(potential_threats),
        'Total Events': len(normal_events) + len(potential_threats)
    }


def collect_data():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Collect data
    collected_data = {
        'System Information': collect_system_information(),
        'Network Traffic': collect_network_traffic(),
        'Security Events': collect_security_events('Security'),
    }

    return collected_data
