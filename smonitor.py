import json

import psutil
import threading

from flask import Flask, jsonify, session, request
from flask_socketio import SocketIO, emit

app = Flask(__name__)
with open('config.json') as f_config:
    config = json.load(f_config)
app.config['SECRET_KEY'] = config['server']['secret']
socket_io = SocketIO(app, async_mode='gevent')

clients = 0
clients_lock = threading.Lock()
worker_thread = None
worker_thread_lock = threading.Lock()


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/config')
def get_config():
    conf = dict(config['monitor'])
    conf['port'] = config['server']['port']
    return jsonify(conf)


@socket_io.on('connect')
def socket_connect():
    global clients, worker_thread
    with clients_lock:
        clients += 1
        print('[Socket Connected] ID=%s, total clients: %d' % (request.sid, clients))
        if worker_thread is None:
            with worker_thread_lock:
                worker_thread = socket_io.start_background_task(target=status_worker)
    emit('connected', {'clients': clients})


@socket_io.on('disconnect')
def socket_disconnect():
    global clients
    with clients_lock:
        clients -= 1
        print('[Socket Disconnected] ID=%s, total clients: %d' % (request.sid, clients))


@socket_io.on('ping')
def socket_ping():
    emit('pong')


def status_worker():
    global worker_thread
    print('[Background] Worker Started')
    while clients:
        vm = psutil.virtual_memory()
        sys_partition = None
        boot_partition = None
        other_partitions = None
        other_partitions_total = 0
        other_partitions_used = 0
        for part in psutil.disk_partitions():
            usage = psutil.disk_usage(part.mountpoint)
            if part.mountpoint == '/':
                sys_partition = {'total': usage.total, 'percent': usage.percent}
            elif part.mountpoint == '/boot/efi':
                boot_partition = {'total': usage.total, 'percent': usage.percent}
            else:
                other_partitions_total += usage.total
                other_partitions_used += usage.used
        if other_partitions_total > 0:
            other_partitions = {
                'total': other_partitions_total,
                'percent': round(1000.0 * other_partitions_used / other_partitions_total) / 10.0
            }
        status = {
            'cpu': {
                'count': psutil.cpu_count(),
                'percent': psutil.cpu_percent()
            },
            'memory': {
                'total': vm.total,
                'percent': vm.percent
            },
            'disk': {
                'system': sys_partition,
                'boot': boot_partition,
                'others': other_partitions
            },
            'boot_time': psutil.boot_time()
        }
        socket_io.emit('status', status, broadcast=True)
        socket_io.sleep(config['monitor']['interval'])
    with worker_thread_lock:
        worker_thread = None
    print('[Background] Worker Terminated')


if __name__ == '__main__':
    socket_io.run(app, host=config['server']['host'], port=config['server']['port'])
