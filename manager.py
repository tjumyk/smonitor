import json
import subprocess
import sys
import threading

from flask import Flask, jsonify

app = Flask(__name__)
with open('config.json') as f:
    config = json.load(f)
process = None
process_lock = threading.Lock()


@app.route('/')
def get_index():
    mode = config['manager']['mode']
    info = "mode=%s" % mode
    if mode == 'self' and process is not None:
        info += " monitor_pid=%s" % str(process.pid)
    host = config['server']['host']
    if host == '0.0.0.0':
        host = 'localhost'  # Windows-compatible
    monitor_address = 'http://%s:%d' % (host, config['server']['port'])
    return "<html><body><h1>SMonitor Manager</h1><p>%s</p><p>Monitor Server: <a href='%s'>%s</a></p></body></html>" % \
           (info, monitor_address, monitor_address)


@app.route('/restart')
def restart():
    _config = config['manager']
    mode = _config['mode']
    try:
        if mode == 'self':
            _restart()
        elif mode == 'supervisor':
            subprocess.run(['supervisorctl', 'restart', 'smonitor'], check=True, stdout=subprocess.PIPE)
        else:
            raise RuntimeError('Mode (%s) is not supported' % mode)
    except Exception as e:
        return 500, jsonify(error=str(e))
    return jsonify(success=True)


def _restart():
    global process
    with process_lock:
        if process:
            process.kill()
        process = subprocess.Popen([sys.executable, 'app.py'])


if config['manager']['mode'] == 'self':
    _restart()

if __name__ == '__main__':
    app.run(host=config['manager']['host'], port=config['manager']['port'])
