from gevent import monkey

monkey.patch_all()

import base64
import gzip
import json
import os
import socket
import threading
import time
from collections import defaultdict
from urllib.parse import urlencode

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request, Response
from flask_socketio import SocketIO, emit, join_room, leave_room

import collector
import loggers
from auth_connect import oauth
import repository
import personal
from auth_connect.oauth import requires_login

logger = loggers.get_logger(__name__)

LOCAL_HOST = 'local'

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
    data = collector.get_status().get('basic')  # pull the 'basic' info

    if request.args.get('encrypted'):
        return Response(_encrypt(data), mimetype='application/octet-stream')
    elif request.remote_addr != '127.0.0.1':
        return jsonify(error='Access forbidden'), 403
    return jsonify(data)


@app.route('/api/full_status')
@requires_login
def get_full_status():
    active_users = set()
    active_users_value = request.args.get('u')
    if active_users_value:
        for uid in active_users_value.split(','):
            uid = uid.strip()
            if uid:
                active_users.add(uid)
    data = collector.get_status(active_users)

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


@app.route('/api/self_restart')  # removed @requires_login
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
            'user_hosts': personal.get_user_hosts(user.name) if user else {},
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
    if config['monitor']['mode'] == 'app':
        join_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        logger.info('[Subscribe Full Status] ID=%s, Host=%s, TotalSubscribers=%d' % (request.sid, host, subscribers))
    else:
        join_room(LOCAL_HOST)
        subscribers = len(socket_io.server.manager.rooms['/'].get(LOCAL_HOST) or ())
        logger.info('[Subscribe Full Status] ID=%s, TotalSubscribers=%d' % (request.sid, subscribers))


@socket_io.on('disable_full_status')
def socket_disable_full_status(host):
    if config['monitor']['mode'] == 'app':
        leave_room(host)
        subscribers = len(socket_io.server.manager.rooms['/'].get(host) or ())
        logger.info('[Unsubscribe Full Status] ID=%s, Host=%s, TotalSubscribers=%d' %
                    (request.sid, host, subscribers))
    else:
        leave_room(LOCAL_HOST)
        subscribers = len(socket_io.server.manager.rooms['/'].get(LOCAL_HOST) or ())
        logger.info('[Unsubscribe Full Status] ID=%s, TotalSubscribers=%d' %
                    (request.sid, subscribers))


@socket_io.on('enable_personal_status')
def socket_enable_personal_status(host):
    client = clients[request.sid]
    if config['monitor']['mode'] == 'app':
        host_user = client['user_hosts'].get(host)
        if not host_user:
            logger.warning('[Subscribe Personal Status Warning] No host user mapping found for: ID=%s, Host=%s)'
                           % (request.sid, host))
            return
        room_id = _get_personal_room(host, host_user)
        join_room(room_id)
        subscribers = len(socket_io.server.manager.rooms['/'].get(room_id) or ())
        logger.info('[Subscribe Personal Status] ID=%s, Host=%s, User=%s, TotalSubscribers=%d'
                    % (request.sid, host, host_user, subscribers))
    else:
        host_user = client['user_hosts'].get(LOCAL_HOST)
        if not host_user:
            logger.warning('[Subscribe Personal Status Warning] No host user mapping found for: ID=%s)' % request.sid)
            return
        room_id = _get_personal_room(LOCAL_HOST, host_user)
        join_room(room_id)
        subscribers = len(socket_io.server.manager.rooms['/'].get(room_id) or ())
        logger.info('[Subscribe Personal Status] ID=%s, User=%s, TotalSubscribers=%d'
                    % (request.sid, host_user, subscribers))


@socket_io.on('disable_personal_status')
def socket_disable_personal_status(host):
    client = clients[request.sid]
    if config['monitor']['mode'] == 'app':
        host_user = client['user_hosts'].get(host)
        if not host_user:
            logger.warning('[Unsubscribe Personal Status Warning] No host user mapping found for: ID=%s, Host=%s)'
                           % (request.sid, host))
            return
        room_id = _get_personal_room(host, host_user)
        leave_room(room_id)
        subscribers = len(socket_io.server.manager.rooms['/'].get(room_id) or ())
        logger.info('[Unsubscribe Personal Status] ID=%s, Host=%s, User=%s, TotalSubscribers=%d' %
                    (request.sid, host, host_user, subscribers))
    else:
        host_user = client['user_hosts'].get(LOCAL_HOST)
        if not host_user:
            logger.warning('[Unsubscribe Personal Status Warning] No host user mapping found for: ID=%s)' % request.sid)
            return
        room_id = _get_personal_room(LOCAL_HOST, host_user)
        leave_room(room_id)
        subscribers = len(socket_io.server.manager.rooms['/'].get(room_id) or ())
        logger.info('[Unsubscribe Personal Status] ID=%s, User=%s, TotalSubscribers=%d' %
                    (request.sid, host_user, subscribers))


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
        result = _get_remote_data(host, '/api/self_update', None, (0.2, 30), False)
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
            rooms = socket_io.server.manager.rooms.get('/')
            active_users = _get_active_users(rooms, LOCAL_HOST)
            if active_users:
                full_status = collector.get_status(active_users)
                socket_io.emit('status', full_status['basic'])
                _full_status = full_status.get('full')
                if _full_status:
                    socket_io.emit('full_status', _full_status, room=LOCAL_HOST)
                for user, personal_status in full_status.get('personal', {}).items():
                    room_id = _get_personal_room(LOCAL_HOST, user)
                    socket_io.emit('personal_status', personal_status, room=room_id)
            else:
                socket_io.emit('status', collector.get_status().get('basic'))
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
    personal_status_map = defaultdict(dict)
    info_map = {}
    rooms = socket_io.server.manager.rooms.get('/')

    batch_start_time = time.time()
    for host_group in config['monitor']['host_groups']:
        for host in host_group['hosts']:
            name = host['name']
            retry = host_retry.get(name)
            if retry is None or retry['wait_remain'] <= 0:
                active_users = _get_active_users(rooms, name)
                if active_users:
                    query_args = {'u': ','.join(active_users)}
                    status = _get_remote_data(host, '/api/full_status', query_args, request_timeout, True)
                    if 'error' in status:
                        status_map[name] = status
                        full_status_map[name] = status
                        for user in active_users:
                            if user == collector.GLOBAL_ACTIVE_USER:
                                continue
                            personal_status_map[user][name] = status
                    else:
                        status_map[name] = status['basic']
                        full_status = status.get('full')
                        if full_status:
                            full_status_map[name] = full_status
                        for user, personal_status in status.get('personal', {}).items():
                            personal_status_map[user][name] = personal_status
                else:
                    status = _get_remote_data(host, '/api/status', None, request_timeout, True)
                    status_map[name] = status
                info = {}
                existing_info = host_info.get(name)
                if 'error' in status or existing_info is None or 'error' in existing_info:
                    info = _get_remote_data(host, '/api/info', None, request_timeout, True)
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
                for user, status_dict in personal_status_map.items():
                    for host_name, status in status_dict.items():
                        room_id = _get_personal_room(host_name, user)
                        socket_io.emit('personal_status', {host_name: status}, room=room_id)
                info_map.clear()
                status_map.clear()
                full_status_map.clear()
                personal_status_map.clear()
                batch_start_time = time.time()

    # the remaining data to send
    if info_map:
        socket_io.emit('info', info_map)
    if status_map:
        socket_io.emit('status', status_map)
    for host_name, status in full_status_map.items():
        socket_io.emit('full_status', {host_name: status}, room=host_name)
    for user, status_dict in personal_status_map.items():
        for host_name, status in status_dict.items():
            room_id = _get_personal_room(host_name, user)
            socket_io.emit('personal_status', {host_name: status}, room=room_id)


def _get_remote_data(host, path, args, timeout, encrypted):
    address = host['address']
    port_num = host.get('port') or config['server']['port']
    response = None
    data = None
    try:
        url = "http://%s:%d%s" % (address, port_num, path)
        args = args or {}
        if encrypted:
            args['encrypted'] = 1
        if args:
            url += "?" + urlencode(args)
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


def _get_personal_room(host_name: str, user_name: str) -> str:
    return '%s:%s' % (host_name, user_name)


def _get_active_users(rooms, host) -> set:
    if not rooms:
        return set()
    active_users = set()
    for room_id, subscribers in rooms.items():
        if not room_id or not subscribers:  # lobby or empty room
            continue
        if room_id == host:  # requesting full status
            active_users.add(collector.GLOBAL_ACTIVE_USER)
        elif room_id.startswith(host + ':'):  # requesting personal status
            uid = room_id.split(':', 1)[1]
            active_users.add(uid)
    return active_users


collector.init()

if __name__ == '__main__':
    try:
        socket_io.run(app, host=config['server']['host'], port=config['server']['port'])
    finally:
        collector.clean_up()  # FIXME will not be called if in WSGI mode
