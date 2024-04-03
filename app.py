import time
from threading import Thread

from flask import Flask, render_template, jsonify, request

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
        time.sleep(15)  # Update data every 5 seconds


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
        return 'Data is being collected...'


@app.route('/file-system')
def file_system():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'File System Events', 'data': latest_data['File System Events']})
    else:
        return 'Data is being collected...'


@app.route('/network-traffic')
def network_traffic():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'Network Traffic', 'data': latest_data['Network Traffic']})
    else:
        return 'Data is being collected...'


@app.route('/security-events')
def security_events():
    if latest_data:

        return render_template('data_page.html',
                               data={'key': 'Security Events', 'data': latest_data['Security Events']})
    else:
        return 'Data is being collected...'


@app.route('/system-logs')
def system_logs():
    if latest_data:
        return render_template('data_page.html',
                               data={'key': 'System Logs', 'data': latest_data['System Logs']})
    else:
        return 'Data is being collected...'


@app.route('/get_latest_data')
def get_latest_data():
    if latest_data:
        return jsonify(latest_data)
    else:
        return jsonify({'message': 'No data available yet'})


@app.route('/get_filtered_data')
def get_filtered_data():
    filter_key = request.args.get('key', None)
    if filter_key is None:
        return jsonify({'message': 'Filter key not provided'})

    filtered_value = latest_data.get(filter_key, None)
    if filtered_value is not None:
        return jsonify({filter_key: filtered_value})
    else:
        return jsonify({'message': f'No data found for key {filter_key}'})


if __name__ == "__main__":
    app.run(debug=True)
