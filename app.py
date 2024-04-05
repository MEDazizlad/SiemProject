import time
from threading import Thread

from flask import Flask, request, render_template, jsonify

from DataOperations.collect_data import collect_data

app = Flask(__name__)

# Global variable to store latest data (replace with shared data structure if needed)
latest_data = None


def update_data():
    global latest_data
    while True:
        collected_data = collect_data()
        # save_data(collected_data) // had no time to implement db saving
        latest_data = collected_data
        time.sleep(15)  # Update data every 15 seconds


data_thread = Thread(target=update_data)
data_thread.daemon = True
data_thread.start()


@app.route('/')
def index():
    if latest_data:
        return render_template('index.html',
                               data={'key': 'System Information', 'data': latest_data['System Information']}
                               )
    else:
        return render_template('loading.html')


@app.route('/network-traffic')
def network_traffic():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'Network Traffic', 'data': latest_data['Network Traffic']})
    else:
        return render_template('loading.html')


@app.route('/security-events')
def security_events():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'Security Events', 'data': latest_data['Security Events']})
    else:
        return render_template('loading.html')


@app.route('/reload')
def reload_page():
    return jsonify(success=True), 200


@app.route('/js/reload.js')
def reload_js():
    return render_template('reload.js')


@app.route('/get_latest_data')
def get_latest_data():
    if latest_data:
        return jsonify(latest_data)
    else:
        return jsonify({'message': 'No data available yet'})


@app.route('/get_filtered_data')
def get_filtered_data():
    filter_key = request.args.get('key', None)
    page_number = int(request.args.get('pageNumber', 1))  # Default to page 1 if not provided
    items_per_page = 20  # Adjust as needed

    if filter_key is None:
        return jsonify({'message': 'Filter key not provided'})

    collected_data = latest_data.get(filter_key, None)
    if collected_data is not None:
        if filter_key == 'Network Traffic':
            traffic_data = collected_data.get('Traffic Data', {})
            traffic_metrics = collected_data.get('Traffic Metrics', {})

            if traffic_data:
                total_packets = traffic_data.get('Total Packets', 0)
                total_distinct_destination_ip = traffic_data.get('Total Distinct Source IPs', 0)
                total_distinct_source_ip = traffic_data.get('Total Distinct Destination IPs', 0)
                packet_details = traffic_data.get('Packet Details', [])
                distinct_protocols = traffic_data.get('Distinct Protocols', [])
                distinct_destination_ip = traffic_data.get('Distinct Destination IPs', [])
                distinct_source_ip = traffic_data.get('Distinct Source IPs', [])
                # Calculate start and end indices for the subset
                start_index = (page_number - 1) * items_per_page
                end_index = min(start_index + items_per_page, total_packets)
                end_index_dest = min(start_index + items_per_page, total_distinct_destination_ip)
                end_index_source = min(start_index + items_per_page, total_distinct_source_ip)
                # Extract the subset of packet details
                subset_packet_details = packet_details[start_index:end_index]
                subset_distinct_destination_ip = distinct_destination_ip[start_index:end_index_dest]
                subset_distinct_source_ip = distinct_source_ip[start_index:end_index_source]
                # Prepare response including metadata
                response_data = {
                    filter_key: {
                        'Traffic Data': {
                            'Total Packets': total_packets,
                            'Packet Details': subset_packet_details,
                            'Distinct Protocols': distinct_protocols,
                            'Distinct Source IPs': subset_distinct_source_ip,
                            'Total Distinct Source IPs': total_distinct_source_ip,
                            'Distinct Destination IPs': subset_distinct_destination_ip,
                            'Total Distinct Destination IPs': total_distinct_destination_ip,
                        },
                        'Traffic Metrics': traffic_metrics
                    }
                }
                return jsonify(response_data)
            else:
                return jsonify({'message': f'No traffic data found for key {filter_key}'})

        elif filter_key == 'Security Events':
            potential_threats = collected_data.get('Potential Threats', {})
            total_events = collected_data.get('Total Events', None)
            total_threats = collected_data.get('Total Threats', None)
            if potential_threats:
                start_index = (page_number - 1) * items_per_page
                end_index = min(start_index + items_per_page, total_threats)
                subset_potential_threats = potential_threats[start_index:end_index]
                response_data = {
                    filter_key: {
                        'Potential Threats': subset_potential_threats,
                        'Total Threats': total_threats,
                        'Total Events': total_events
                    }
                }
                return jsonify(response_data)
        elif filter_key == 'System Information':
            return jsonify({filter_key: collected_data})
    
        else:
            return jsonify({'message': f'Pagination not supported for {filter_key} data'})

    else:
        return jsonify({'message': f'No data found for key {filter_key}'})


if __name__ == "__main__":
    app.run(debug=True)
