import json
import sys
import threading
import time

import psutil
import requests
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from gevent import monkey
from requests.adapters import HTTPAdapter

import pynvml

monkey.patch_all()

app = Flask(__name__)
with open('config.json') as f_config:
    config = json.load(f_config)
app.config['SECRET_KEY'] = config['server']['secret']
socket_io = SocketIO(app, async_mode='gevent')
room_status_collection = 'status_collection'

clients = 0
clients_lock = threading.Lock()
worker_thread = None
worker_thread_lock = threading.Lock()

nvml_inited = False
static_info = {
    'public': {},
    'private': {}
}
host_info = {}


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/config')
def get_config():
    _config = dict(config['monitor'])
    _config['port'] = config['server']['port']
    return jsonify(_config)


@app.route('/api/info')
def get_static_info():
    return jsonify(static_info['public'])


@app.route('/api/status')
def get_status():
    return jsonify(_get_status())


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
        emit('info', static_info['public'])


@socket_io.on('disconnect')
def socket_disconnect():
    global clients
    with clients_lock:
        clients -= 1
        print('[Socket Disconnected] ID=%s, total clients: %d' % (request.sid, clients))


@socket_io.on('ping')
def socket_ping():
    emit('pong')


def _init():
    global nvml_inited
    _update_psutil_static_info()
    try:
        pynvml.nvmlInit()
        nvml_inited = True
        print('[NVML] NVML Initialized')
        _update_nvml_static_info()
    except pynvml.NVMLError as e:
        print('[NVML] NVML Not Initialized: %s' % str(e))
        pass


def _clean_up():  # TODO when to call this?
    if nvml_inited:
        try:
            pynvml.nvmlShutdown()
            print('[NVML] NVML Shutdown')
        except pynvml.NVMLError as e:
            print('[NVML] NVML Failed to Shutdown: %s' % str(e))
            pass


def _get_status():
    status = _get_status_psutil()
    if nvml_inited:
        status['gpu'] = _get_status_nvml()
    return status


def _status_worker():
    global worker_thread
    print('[Status Worker] Worker Started')
    interval = config['monitor']['interval']
    app_mode = config['monitor']['mode'] == 'app'
    request_timeout = (0.2, interval)
    batch_timeout = min(0.2, interval)

    session = _build_session()
    host_retry = {}
    while clients:
        start_time = time.time()
        if app_mode:
            status_map = {}
            info_map = {}
            batch_start_time = time.time()
            for host_group in config['monitor']['host_groups']:
                for host in host_group['hosts']:
                    name = host['name']
                    retry = host_retry.get(name)
                    if retry is None or retry['wait_remain'] <= 0:
                        status = _get_remote_data(host, '/api/status', request_timeout, session)
                        status_map[name] = status
                        info = {}
                        existing_info = host_info.get(name)
                        if 'error' in status or existing_info is None or 'error' in existing_info:
                            info = _get_remote_data(host, '/api/info', request_timeout, session)
                            info_map[name] = info
                            host_info[name] = info
                        if 'error' in status or 'error' in info:
                            if retry is not None:
                                retry['wait'] = min(20, retry['wait'] * 2)
                                retry['wait_remain'] = retry['wait']
                            else:
                                host_retry[name] = {
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
                        socket_io.emit('status', status_map)
                        info_map.clear()
                        status_map.clear()
                        batch_start_time = time.time()
            if info_map:
                socket_io.emit('info', info_map)
            if status_map:
                socket_io.emit('status', status_map)
        else:
            socket_io.emit('status', _get_status())
        elapsed_time = time.time() - start_time
        if elapsed_time < interval:
            socket_io.sleep(interval - elapsed_time)
        else:
            print('[Status Worker] Iteration slower than configured interval: %ds' % elapsed_time)
    with worker_thread_lock:
        worker_thread = None
    print('[Status Worker] Worker Terminated')


def _build_session():
    session = requests.session()
    adapter = HTTPAdapter(pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def _get_remote_data(host, path, timeout, session):
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


def _update_psutil_static_info():
    vm = psutil.virtual_memory()
    sys_partition = None
    boot_partition = None
    other_partitions = None
    other_partitions_total = 0
    other_partitions_used = 0
    for part in psutil.disk_partitions():
        usage = psutil.disk_usage(part.mountpoint)
        if part.mountpoint == '/':
            sys_partition = {'total': usage.total}
        elif part.mountpoint == '/boot/efi':
            boot_partition = {'total': usage.total}
        else:
            other_partitions_total += usage.total
            other_partitions_used += usage.used
    if other_partitions_total > 0:
        other_partitions = {
            'total': other_partitions_total
        }
    static_info['public'].update({
        'cpu': {
            'count': psutil.cpu_count()
        },
        'memory': {
            'total': vm.total
        },
        'disk': {
            'system': sys_partition,
            'boot': boot_partition,
            'others': other_partitions
        },
        'boot_time': psutil.boot_time()
    })


def _update_nvml_static_info():
    driver_version = pynvml.nvmlSystemGetDriverVersion().decode()
    nvml_version = pynvml.nvmlSystemGetNVMLVersion().decode()
    device_count = pynvml.nvmlDeviceGetCount()
    devices = []
    devices_handles = []
    for i in range(device_count):
        handle = pynvml.nvmlDeviceGetHandleByIndex(i)
        name = pynvml.nvmlDeviceGetName(handle).decode()
        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        devices.append({
            'index': i,
            'name': name,
            'memory': {
                'total': mem_info.total
            }
        })
        devices_handles.append(handle)
    static_info['public'].update({
        'gpu': {
            'driver': driver_version,
            'nvml': nvml_version,
            'devices': devices
        }
    })
    static_info['private'].update({
        'gpu': {
            'handles': devices_handles
        }
    })


def _get_status_psutil():
    vm = psutil.virtual_memory()
    sys_partition = None
    boot_partition = None
    other_partitions = None
    other_partitions_total = 0
    other_partitions_used = 0
    for part in psutil.disk_partitions():
        usage = psutil.disk_usage(part.mountpoint)
        if part.mountpoint == '/':
            sys_partition = {'percent': usage.percent}
        elif part.mountpoint == '/boot/efi':
            boot_partition = {'percent': usage.percent}
        else:
            other_partitions_total += usage.total
            other_partitions_used += usage.used
    if other_partitions_total > 0:
        other_partitions = {
            'percent': round(1000.0 * other_partitions_used / other_partitions_total) / 10.0
        }
    status = {
        'cpu': {
            'percent': psutil.cpu_percent()
        },
        'memory': {
            'percent': vm.percent
        },
        'disk': {
            'system': sys_partition,
            'boot': boot_partition,
            'others': other_partitions
        }
    }
    return status


def _get_status_nvml():
    devices_status = []
    for handle in static_info['private']['gpu']['handles']:
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        process_info = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
        _status = {
            'utilization': {'gpu': util.gpu, 'memory': util.memory},
            'memory': {
                'percent': int(1000.0 * mem_info.used / mem_info.total) / 10.0
            },
            'processes': len(process_info)
        }
        # info['processes'] = [{'pid': p.pid, 'memory': p.usedGpuMemory} for p in process_info]
        devices_status.append(_status)
    status = {
        'devices': devices_status
    }
    return status


_init()

if __name__ == '__main__':
    port = config['server']['port']
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
        config['server']['port'] = port
    socket_io.run(app, host=config['server']['host'], port=port)
