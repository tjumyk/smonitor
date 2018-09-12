from gevent import monkey

monkey.patch_all()

import base64
import gzip
import json
import os
import socket
import threading
import time

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request, Response
from flask_socketio import SocketIO, emit, join_room, leave_room

import collector
import loggers
import oauth
import repository
from oauth import requires_login

logger = loggers.get_logger(__name__)

config = None
if os.path.isfile('config.json'):
    with open('config.json') as f_config:
        config = json.load(f_config)
else:
    print('Configuration file "config.json" was not found. Please create it and put it in the current working '
          'directory.\nIn the root folder of this repository, "config_app.json" is an example configuration for '
          'an app server and "config_node.json" is an example configuration for a node server.')
    exit(1)

app = Flask(__name__)
app.config['SECRET_KEY'] = config['server']['secret']

cookie_name = config['server'].get('cookie_name')
if cookie_name:
    app.config['SESSION_COOKIE_NAME'] = cookie_name
cookie_path = config['server'].get('cookie_path')
if cookie_path:
    app.config['SESSION_COOKIE_PATH'] = cookie_path

socket_io = SocketIO(app, async_mode='gevent')

session = requests.session()

clients = {}
clients_lock = threading.Lock()
worker_thread = None
worker_thread_lock = threading.Lock()

host_info = {}
enabled_full_status = False

_crypt = Fernet(base64.urlsafe_b64encode(config['security']['secret'].encode('utf-8')))

oauth.init_app(app)


def _encrypt(content):
    raw = json.dumps(content).encode('utf-8')
    zipped = gzip.compress(raw)
    return base64.urlsafe_b64decode(_crypt.encrypt(zipped))


def _decrypt(content):
    zipped = _crypt.decrypt(base64.urlsafe_b64encode(content))
    raw = gzip.decompress(zipped)
    return json.loads(raw.decode('utf-8'))


@app.route('/')
@requires_login
def index():
    return app.send_static_file('index.html')


@app.route('/api/config')
@requires_login
def get_config():
    _config = dict(config['monitor'])
    _config['port'] = config['server']['port']
    _config['package'] = collector.get_static_info()['package']
    user = oauth.get_user()
    if user:
        _config['user'] = user.to_dict()
    return jsonify(_config)


@app.route('/api/info')
@requires_login
def get_static_info():
    data = collector.get_static_info()

    if request.args.get('encrypted'):
        return Response(_encrypt(data), mimetype='application/octet-stream')
    elif request.remote_addr != '127.0.0.1':
        return jsonify(error='Access forbidden'), 403
    return jsonify(data)


@app.route('/api/status')
@requires_login
def get_status():
    data = collector.get_status()

    if request.args.get('encrypted'):
        return Response(_encrypt(data), mimetype='application/octet-stream')
    elif request.remote_addr != '127.0.0.1':
        return jsonify(error='Access forbidden'), 403
    return jsonify(data)


@app.route('/api/full_status')
@requires_login
def get_full_status():
    data = collector.get_full_status()

    if request.args.get('encrypted'):
        return Response(_encrypt(data), mimetype='application/octet-stream')
    elif request.remote_addr != '127.0.0.1':
        return jsonify(error='Access forbidden'), 403
    return jsonify(data)


@app.route('/api/check_update')
@requires_login
def check_update():
    logger.info('[Check Update] Started')
    try:
        latest_label, repo_label, runtime_label = _check_update()
        return jsonify(repo_label=repo_label, runtime_label=runtime_label, latest_label=latest_label)
    except Exception as e:
        error = str(e)
        logger.error('[Check Update] Failed: %s' % error)
        return jsonify(error=error), 500


@app.route('/api/self_update')
@requires_login
def self_update():
    logger.info('[Self Update] Started')
    try:
        latest_label, repo_label, runtime_label = _check_update()
        if runtime_label == latest_label:  # implies repo_label == latest_label
            logger.info('[Self Update] Already up-to-date')
            return jsonify(success=True, already_latest=True, label=latest_label)
        if repo_label != latest_label:
            repository.pull()
        socket_io.start_background_task(target=_restart)
    except Exception as e:
        error = str(e)
        logger.error('[Self Update] Failed: %s' % error)
        return jsonify(error=error), 500
    logger.info('[Self Update] Succeeded')
    return jsonify(success=True, repo_label=repo_label, runtime_label=runtime_label, latest_label=latest_label)


@app.route('/api/self_restart')
@requires_login
def self_restart():
    logger.info('[Self Restart] Started')
    socket_io.start_background_task(target=_restart)
    return jsonify(success=True)


@socket_io.on('connect')
def socket_connect():
    try:
        user = oauth.get_user()  # will return None if OAuth is skipped
    except oauth.OAuthError:
        return False

    global worker_thread
    with clients_lock:
        sid = request.sid
        address = None
        if config['server'].get('behind_proxy'):
            address = request.environ.get('HTTP_X_REAL_IP')
        if address is None:
            address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        new_client = {
            'short_id': sid[-6:],
            'address': address,
            'hostname': None,
            'user': user.to_dict() if user else None,
            'user_agent': user_agent
        }
        clients[sid] = new_client
        logger.info('[Socket Connected] ID=%s, IP=%s, UA=%s, TotalClients=%d' %
                    (sid, address, user_agent, len(clients)))
        with worker_thread_lock:
            if worker_thread is None:
                worker_thread = socket_io.start_background_task(target=_status_worker)
    if config['monitor']['mode'] == 'app':
        emit('info', host_info)
    else:
        emit('info', collector.get_static_info())
    try:
        new_client['hostname'] = socket.gethostbyaddr(new_client['address'])[0]
    except socket.herror:
        pass
    socket_io.emit('clients', clients)


@socket_io.on('disconnect')
def socket_disconnect():
    with clients_lock:
        sid = request.sid
        if sid in clients:
            del clients[sid]
        if clients:
            socket_io.emit('clients', clients)
        logger.info('[Socket Disconnected] ID=%s, TotalClients=%d' % (sid, len(clients)))


@socket_io.on('enable_full_status')
def socket_enable_full_status(host):
    global enabled_full_status
    if config['monitor']['mode'] == 'app':
        join_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        logger.info('[Subscribe Full Status] ID=%s, Host=%s, TotalSubscribers=%d' % (request.sid, host, subscribers))
    else:
        enabled_full_status = True


@socket_io.on('disable_full_status')
def socket_disable_full_status(host):
    global enabled_full_status
    if config['monitor']['mode'] == 'app':
        leave_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        logger.info('[Unsubscribe Full Status] ID=%s, Host=%s, TotalSubscribers=%d' %
                    (request.sid, host, subscribers))
    else:
        enabled_full_status = False


@socket_io.on('update')
def socket_update(host_id):
    if config['monitor']['mode'] != 'app':
        logger.error('Socket update is only for remote host update in app mode')
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
        result = _get_remote_data(host, '/api/self_update', (0.2, 30), False)
        if result.get('success'):
            if result.get('already_latest'):
                emit('update_result', {host_id: result})
            else:
                updated = False
                if host_id in host_info:
                    del host_info[host_id]  # force update
                for _ in range(5):
                    time.sleep(config['monitor']['interval'])
                    info = host_info.get(host_id)
                    if info is None:  # not yet ready
                        continue
                    if 'error' in info:  # connection failed
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
                    emit('update_result', {
                        host_id: {
                            'error': {
                                "type": "restart_daemon",
                                "message": "Failed to restart daemon"
                            }
                        }
                    })
        else:
            emit('update_result', {host_id: result})


def _check_update():
    labels = repository.fetch()
    repo_label = labels['head']
    latest_label = labels['fetch_head']
    runtime_label = collector.get_static_info()['package']['label']
    return latest_label, repo_label, runtime_label


def _restart():
    time.sleep(1)
    logger.info('[Restart] Calling manager to restart')
    requests.get("http://%s:%d/restart" % (config['manager']['host'], config['manager']['port']))


def _status_worker():
    global worker_thread
    logger.info('[Status Worker] Worker Started')
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
            logger.warning('[Status Worker] Iteration slower than configured interval: %ds' % elapsed_time)
    with worker_thread_lock:
        worker_thread = None
    logger.info('[Status Worker] Worker Terminated')


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
                    status = _get_remote_data(host, '/api/full_status', request_timeout, True)
                    if 'error' in status:
                        status_map[name] = status
                        full_status_map[name] = status
                    else:
                        status_map[name] = status['basic']
                        full_status_map[name] = status['full']
                else:
                    status = _get_remote_data(host, '/api/status', request_timeout, True)
                    status_map[name] = status
                info = {}
                existing_info = host_info.get(name)
                if 'error' in status or existing_info is None or 'error' in existing_info:
                    info = _get_remote_data(host, '/api/info', request_timeout, True)
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


def _get_remote_data(host, path, timeout, encrypted):
    address = host['address']
    port_num = host.get('port') or config['server']['port']
    response = None
    data = None
    try:
        url = "http://%s:%d%s" % (address, port_num, path)
        if encrypted:
            url += '?encrypted=1'
        response = session.get(url, timeout=timeout)
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
                    "message": "Error response (%d) when requesting data from remote host" %
                               response.status_code
                }
            }
        else:
            try:
                content = response.content
                if encrypted:
                    data = _decrypt(content)
                else:
                    data = json.loads(content.decode())
            except InvalidToken as e:
                data = {
                    "error": {
                        "type": "remote_status_decryption",
                        "message": "Failed to decrypt data from remote host",
                        "exception": str(e)
                    }
                }
            except Exception as e:
                data = {
                    "error": {
                        "type": "remote_status_parsing",
                        "message": "Failed to parse data from remote host",
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
