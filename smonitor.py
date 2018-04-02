import json

import psutil
import pynvml
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

    nvml_inited = False
    gpu_info_static = None
    try:
        pynvml.nvmlInit()
        nvml_inited = True
        print('[NVML] NVML Initialized')
        gpu_info_static = _get_nvml_static_info()
    except pynvml.NVMLError as e:
        print('[NVML] NVML Not Initialized: %s' % str(e))
        pass

    while clients:
        status = _get_status_psutil()
        if gpu_info_static:
            status.update(_get_status_nvml(gpu_info_static))
        socket_io.emit('status', status, broadcast=True)
        socket_io.sleep(config['monitor']['interval'])
    with worker_thread_lock:
        worker_thread = None

    if nvml_inited:
        try:
            pynvml.nvmlShutdown()
            print('[NVML] NVML Shutdown')
        except pynvml.NVMLError as e:
            print('[NVML] NVML Failed to Shutdown: %s' % str(e))
            pass
    print('[Background] Worker Terminated')


def _get_nvml_static_info():
    # driver_version = pynvml.nvmlSystemGetDriverVersion().decode()
    # nvml_version = pynvml.nvmlSystemGetNVMLVersion().decode()
    device_count = pynvml.nvmlDeviceGetCount()
    devices = []
    for i in range(device_count):
        handle = pynvml.nvmlDeviceGetHandleByIndex(i)
        name = pynvml.nvmlDeviceGetName(handle).decode()
        devices.append({
            'index': i,
            'handle': handle,
            'name': name
        })
    gpu_info_static = {
        # 'driver': driver_version,
        # 'nvml': nvml_version,
        'devices': devices
    }
    return gpu_info_static


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
    return status


def _get_status_nvml(static_info):
    devices_info = []
    for device in static_info['devices']:
        info = dict(device)
        del info['handle']  # copy all fields except handle
        handle = device['handle']
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        # process_info = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)

        info['utilization'] = {'gpu': util.gpu, 'memory': util.memory}
        info['memory'] = {
            'total': mem_info.total,
            'percent': int(1000.0 * mem_info.used / mem_info.total) / 10.0
        }
        # info['processes'] = [{'pid': p.pid, 'memory': p.usedGpuMemory} for p in process_info]
        devices_info.append(info)

    status = dict(static_info)
    status['devices'] = devices_info
    return {'gpu': status}


if __name__ == '__main__':
    socket_io.run(app, host=config['server']['host'], port=config['server']['port'])
