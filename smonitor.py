import json
import subprocess
import sys
import threading
import time

import requests
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from gevent import monkey
from requests.adapters import HTTPAdapter

import collector

monkey.patch_all()

app = Flask(__name__)
with open('config.json') as f_config:
    config = json.load(f_config)
app.config['SECRET_KEY'] = config['server']['secret']
socket_io = SocketIO(app, async_mode='gevent')

session = requests.session()
adapter = HTTPAdapter(pool_maxsize=100)
session.mount('http://', adapter)
session.mount('https://', adapter)

clients = 0
clients_lock = threading.Lock()
worker_thread = None
worker_thread_lock = threading.Lock()

host_info = {}
enabled_full_status = False


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/config')
def get_config():
    _config = dict(config['monitor'])
    _config['port'] = config['server']['port']
    _config['package'] = collector.get_static_info()['package']
    return jsonify(_config)


@app.route('/api/info')
def get_static_info():
    return jsonify(collector.get_static_info())


@app.route('/api/status')
def get_status():
    return jsonify(collector.get_status())


@app.route('/api/full_status')
def get_full_status():
    return jsonify(collector.get_full_status())


@app.route('/api/self_update')
def self_update():
    print('[Self Update] Started')
    try:
        subprocess.run(['git', 'fetch'], check=True)
        labels = subprocess.check_output(['git', 'describe', '--always', 'HEAD', 'FETCH_HEAD']).decode().strip().split()
        repo_label = labels[0]
        latest_label = labels[1]
        runtime_label = collector.get_static_info()['package']['label']
        if runtime_label == latest_label:  # implies repo_label == latest_label
            print('[Self Update] Already up-to-date')
            return jsonify(success=True, already_latest=True, label=latest_label)
        if repo_label != latest_label:
            subprocess.run(['git', 'pull'], check=True)
        socket_io.start_background_task(target=_restart)
    except Exception as e:
        error = str(e)
        print('[Self Update] Failed: %s' % error)
        return jsonify(error=error)
    print('[Self Update] Succeeded')
    return jsonify(success=True, repo_label=repo_label, runtime_label=runtime_label, latest_label=latest_label)


@socket_io.on('connect')
def socket_connect():
    global clients, worker_thread
    with clients_lock:
        clients += 1
        print('[Socket Connected] ID=%s, total clients: %d' % (request.sid, clients))
        with worker_thread_lock:
            if worker_thread is None:
                worker_thread = socket_io.start_background_task(target=_status_worker)
    if config['monitor']['mode'] == 'app':
        emit('info', host_info)
    else:
        emit('info', collector.get_static_info())


@socket_io.on('disconnect')
def socket_disconnect():
    global clients
    with clients_lock:
        clients -= 1
        print('[Socket Disconnected] ID=%s, total clients: %d' % (request.sid, clients))


@socket_io.on('enable_full_status')
def socket_enable_full_status(host):
    global enabled_full_status
    if config['monitor']['mode'] == 'app':
        join_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        print('[Subscribe Full Status] ID=%s host: %s, total subscribers: %d' % (request.sid, host, subscribers))
    else:
        enabled_full_status = True


@socket_io.on('disable_full_status')
def socket_disable_full_status(host):
    global enabled_full_status
    if config['monitor']['mode'] == 'app':
        leave_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        print('[Unsubscribe Full Status] ID=%s host: %s, total subscribers: %d' % (request.sid, host, subscribers))
    else:
        enabled_full_status = False


@socket_io.on('update')
def socket_update(host_id):
    if config['monitor']['mode'] != 'app':
        print('[Warning] socket update is only for remote host update in app mode')
        return
    host = None
    for host_group in config['monitor']['host_groups']:
        for _host in host_group['hosts']:
            if _host['name'] == host_id:
                host = _host
                break
        if host:
            break
    if host:
        result = _get_remote_data(host, '/api/self_update', (0.2, 30))
        if result.get('success'):
            if result.get('already_latest'):
                emit('update_result', {host_id: result})
            else:
                updated = False
                del host_info[host_id]  # force update
                for _ in range(5):
                    time.sleep(config['monitor']['interval'])
                    info = host_info.get(host_id)
                    if info is None:  # not yet ready
                        continue
                    label = info['package']['label']
                    if label != result.get('latest_label'):
                        del host_info[host_id]
                    else:
                        updated = True
                        break
                if updated:
                    emit('update_result', {host_id: result})
                else:
                    emit('update_result', {host_id: {'error': 'Failed to restart daemon'}})
        else:
            emit('update_result', {host_id: result})


def _restart():
    time.sleep(1)
    print('[Restart] Calling manager to restart')
    requests.get("http://%s:%d/restart" % (config['manager']['host'], config['manager']['port']))


def _status_worker():
    global worker_thread
    print('[Status Worker] Worker Started')
    interval = config['monitor']['interval']
    app_mode = config['monitor']['mode'] == 'app'
    request_timeout = (0.2, interval)
    batch_timeout = min(0.2, interval)

    host_retry = {}
    while clients:
        start_time = time.time()
        if app_mode:
            _collect_remote_status(host_retry, request_timeout, batch_timeout)
        else:
            if enabled_full_status:
                full_status = collector.get_full_status()
                socket_io.emit('status', full_status['basic'])
                socket_io.emit('full_status', full_status['full'])
            else:
                socket_io.emit('status', collector.get_status())
        elapsed_time = time.time() - start_time
        if elapsed_time < interval:
            socket_io.sleep(interval - elapsed_time)
        else:
            print('[Status Worker] Iteration slower than configured interval: %ds' % elapsed_time)
    with worker_thread_lock:
        worker_thread = None
    print('[Status Worker] Worker Terminated')


def _collect_remote_status(host_retry, request_timeout, batch_timeout):
    status_map = {}
    full_status_map = {}
    info_map = {}
    rooms = socket_io.server.manager.rooms.get('/')

    batch_start_time = time.time()
    for host_group in config['monitor']['host_groups']:
        for host in host_group['hosts']:
            name = host['name']
            retry = host_retry.get(name)
            if retry is None or retry['wait_remain'] <= 0:
                fetch_full_status = False
                if rooms is not None and rooms.get(name):
                    fetch_full_status = True
                if fetch_full_status:
                    status = _get_remote_data(host, '/api/full_status', request_timeout)
                    if 'error' in status:
                        status_map[name] = status
                        full_status_map[name] = status
                    else:
                        status_map[name] = status['basic']
                        full_status_map[name] = status['full']
                else:
                    status = _get_remote_data(host, '/api/status', request_timeout)
                    status_map[name] = status
                info = {}
                existing_info = host_info.get(name)
                if 'error' in status or existing_info is None or 'error' in existing_info:
                    info = _get_remote_data(host, '/api/info', request_timeout)
                    info_map[name] = info
                    host_info[name] = info
                if 'error' in status or 'error' in info:
                    if retry is not None:
                        retry['wait'] = min(20, retry['wait'] * 2)
                        retry['wait_remain'] = retry['wait']
                    else:
                        host_retry[name] = retry = {
                            'wait': 1,
                            'wait_remain': 1
                        }
                else:
                    if retry is not None:
                        del host_retry[name]
                        retry = None
            if retry is not None:
                retry['wait_remain'] -= 1
            if time.time() - batch_start_time > batch_timeout:
                if info_map:
                    socket_io.emit('info', info_map)
                if status_map:
                    socket_io.emit('status', status_map)
                for host_name, status in full_status_map.items():
                    socket_io.emit('full_status', {host_name: status}, room=host_name)
                info_map.clear()
                status_map.clear()
                full_status_map.clear()
                batch_start_time = time.time()

    # the remaining data to send
    if info_map:
        socket_io.emit('info', info_map)
    if status_map:
        socket_io.emit('status', status_map)
    for host_name, status in full_status_map.items():
        socket_io.emit('full_status', {host_name: status}, room=host_name)


def _get_remote_data(host, path, timeout):
    address = host['address']
    port_num = host.get('port') or config['server']['port']
    response = None
    data = None
    try:
        response = session.get("http://%s:%d%s" % (address, port_num, path), timeout=timeout)
    except Exception as e:
        data = {
            "error": {
                "type": "remote_connection",
                "message": "Failed to connect to remote host",
                "exception": str(e)
            }
        }
    if response is not None:
        if response.status_code != 200:
            data = {
                "error": {
                    "type": "remote_status_request",
                    "message": "Error response (%d) when requesting status of remote host" %
                               response.status_code
                }
            }
        else:
            try:
                data = json.loads(response.content.decode())
            except Exception as e:
                data = {
                    "error": {
                        "type": "remote_status_parsing",
                        "message": "Failed to parse status of remote host",
                        "exception": str(e)
                    }
                }
    return data


collector.init()

if __name__ == '__main__':
    try:
        socket_io.run(app, host=config['server']['host'], port=config['server']['port'])
    finally:
        collector.clean_up()  # FIXME will not be called if in WSGI mode
