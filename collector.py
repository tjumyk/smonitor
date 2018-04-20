import platform
import subprocess

import distro
import psutil
from cpuinfo import cpuinfo

import pynvml

_nvml_inited = False
_static_info = {
    'public': {},
    'private': {}
}


def init():
    global _nvml_inited
    _update_package_info()
    _update_platform_info()
    _update_psutil_static_info()
    try:
        pynvml.nvmlInit()
        _nvml_inited = True
        print('[NVML] NVML Initialized')
        _update_nvml_static_info()
    except pynvml.NVMLError as e:
        print('[NVML] NVML Not Initialized: %s' % str(e))
        pass


def clean_up():
    if _nvml_inited:
        try:
            pynvml.nvmlShutdown()
            print('[NVML] NVML Shutdown')
        except pynvml.NVMLError as e:
            print('[NVML] NVML Failed to Shutdown: %s' % str(e))
            pass


def get_static_info():
    return _static_info['public']


def get_status():
    status = _get_status_psutil()
    if _nvml_inited:
        status['gpu'] = _get_status_nvml()
    return status


def get_full_status():
    status = _get_full_status_psutil()
    if _nvml_inited:
        full_status_nvml = _get_full_status_nvml()
        status['basic']['gpu'] = full_status_nvml['basic']
        status['full']['gpu'] = full_status_nvml['full']
    return status


def _get_package_info():
    info = None
    try:
        git_label = subprocess.check_output(["git", "describe", "--always"]).decode().strip()
        info = {
            "label": git_label
        }
    except Exception as e:
        print('[Warning] Failed to get the package information: %s' % str(e))
    return info


def _update_package_info():
    _static_info['public']['package'] = _get_package_info()


def _update_platform_info():
    system = platform.system()
    info = {
        'system': system
    }
    if system == 'Linux':
        name, version, codename = distro.linux_distribution()
        info['distribution'] = {
            'name': name,
            'version': version,
            'codename': codename
        }
    _static_info['public']['platform'] = info


def _update_psutil_static_info():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    sys_partition = None
    boot_partition = None
    other_partitions = None
    other_partitions_total = 0
    partitions = {}
    for part in psutil.disk_partitions():
        device = partitions.get(part.device)
        if device is None:
            device = {
                'name': part.device,
                'fstype': part.fstype,
                # 'opts': part.opts,
                'mount_points': [],
            }
            partitions[part.device] = device
        device['mount_points'].append(part.mountpoint)
    _static_info['private']['disk'] = {
        'partitions': partitions,
        'others': []
    }
    for name, device in partitions.items():
        mount_points = device['mount_points']
        usage = psutil.disk_usage(mount_points[0])
        if '/' in mount_points:
            sys_partition = {'total': usage.total}
            device['category'] = 'system'
            _static_info['private']['disk']['system'] = device
        elif '/boot/efi' in mount_points:
            boot_partition = {'total': usage.total}
            device['category'] = 'boot'
            _static_info['private']['disk']['boot'] = device
        else:
            other_partitions_total += usage.total
            device['category'] = 'others'
            _static_info['private']['disk']['others'].append(device)
        device['total'] = usage.total
    if other_partitions_total > 0:
        other_partitions = {
            'total': other_partitions_total
        }
    cpu_info = cpuinfo.get_cpu_info()
    _static_info['public'].update({
        'cpu': {
            'count': psutil.cpu_count(),
            'cores': psutil.cpu_count(False),
            'brand': cpu_info['brand']
        },
        'memory': {
            'total': vm.total
        },
        'swap': {
            'total': swap.total
        },
        'disk': {
            'system': sys_partition,
            'boot': boot_partition,
            'others': other_partitions,
            'partitions': sorted(partitions.values(), key=lambda d: d['name'])
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
    _static_info['public'].update({
        'gpu': {
            'driver': driver_version,
            'nvml': nvml_version,
            'devices': devices
        }
    })
    _static_info['private'].update({
        'gpu': {
            'handles': devices_handles
        }
    })


def _get_status_psutil():
    vm = psutil.virtual_memory()
    sys_usage = psutil.disk_usage(_static_info['private']['disk']['system']['mount_points'][0])
    sys_partition = {'percent': sys_usage.percent}
    boot_partition = None
    boot_device = _static_info['private']['disk'].get('boot')
    if boot_device:
        boot_usage = psutil.disk_usage(boot_device['mount_points'][0])
        boot_partition = {'percent': boot_usage.percent}
    other_partitions = None
    other_partitions_total = 0
    other_partitions_free = 0
    for other in _static_info['private']['disk']['others']:
        usage = psutil.disk_usage(other['mount_points'][0])
        other_partitions_total += usage.total
        other_partitions_free += usage.free
    if other_partitions_total > 0:
        other_partitions = {
            'percent': round(1000 * (1 - other_partitions_free / other_partitions_total)) / 10
        }
    status = {
        'cpu': {
            'percent': psutil.cpu_percent()
        },
        'memory': {
            'percent': vm.percent,
        },
        'disk': {
            'system': sys_partition,
            'boot': boot_partition,
            'others': other_partitions
        }
    }
    return status


def _get_full_status_psutil():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    sys_partition = None
    boot_partition = None
    boot_device = _static_info['private']['disk'].get('boot')
    other_partitions = None
    other_partitions_total = 0
    other_partitions_free = 0
    partition_usages = {}
    for name, device in _static_info['private']['disk']['partitions'].items():
        usage = psutil.disk_usage(device['mount_points'][0])
        partition_usages[name] = {
            'free': usage.free,
            'used': usage.used,
            'percent': usage.percent
        }
        if name == _static_info['private']['disk']['system']['name']:
            sys_partition = {'percent': usage.percent}
        elif boot_device is not None and name == boot_device['name']:
            boot_partition = {'percent': usage.percent}
        else:
            other_partitions_total += usage.total
            other_partitions_free += usage.free
    if other_partitions_total > 0:
        other_partitions = {
            'percent': round(1000 * (1 - other_partitions_free / other_partitions_total)) / 10
        }

    status = {
        'basic': {
            'cpu': {
                'percent': psutil.cpu_percent()
            },
            'memory': {
                'percent': vm.percent,
            },
            'disk': {
                'system': sys_partition,
                'boot': boot_partition,
                'others': other_partitions
            }
        },
        'full': {
            'cpu': {
                'percents': psutil.cpu_percent(percpu=True)
            },
            'memory': {
                'available': vm.available,
                'used': vm.used,
                'free': vm.free,
                'buffers': vm.buffers,
                'cached': vm.cached,
                'used_percent': round(1000 * vm.used / vm.total) / 10,
                'free_percent': round(1000 * vm.free / vm.total) / 10,
                'buffers_percent': round(1000 * vm.buffers / vm.total) / 10,
                'cached_percent': round(1000 * vm.cached / vm.total) / 10
            },
            'swap': {
                'free': swap.free,
                'percent': swap.percent
            },
            'disk': {
                'partitions': partition_usages
            },
            'users': [{
                'name': u.name,
                'terminal': u.terminal,
                'host': u.host,
                'started': u.started,
                'pid': u.pid
            } for u in psutil.users()]
        }
    }
    return status


def _get_status_nvml():
    devices_status = []
    for handle in _static_info['private']['gpu']['handles']:
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        process_info = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
        devices_status.append({
            'utilization': {'gpu': util.gpu, 'memory': util.memory},
            'memory': {
                'percent': int(1000.0 * mem_info.used / mem_info.total) / 10.0
            },
            'processes': len(process_info)
        })
    status = {
        'devices': devices_status
    }
    return status


def _get_full_status_nvml():
    devices_status = []
    devices_full_status = []
    for handle in _static_info['private']['gpu']['handles']:
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        process_info = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
        devices_status.append({
            'utilization': {'gpu': util.gpu, 'memory': util.memory},
            'memory': {
                'percent': int(1000.0 * mem_info.used / mem_info.total) / 10.0
            },
            'processes': len(process_info)
        })
        full_status = {
            'memory': {
                'free': mem_info.free,
                'used': mem_info.used
            },
            'process_list': [{'pid': p.pid, 'memory': p.usedGpuMemory} for p in process_info]
        }
        try:
            full_status['fan_speed'] = pynvml.nvmlDeviceGetFanSpeed(handle)
        except pynvml.NVMLError_NotSupported:
            pass
        try:
            full_status['temperature'] = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        except pynvml.NVMLError_NotSupported:
            pass
        try:
            full_status['performance'] = pynvml.nvmlDeviceGetPerformanceState(handle)
        except pynvml.NVMLError_NotSupported:
            pass
        try:
            full_status['power'] = {
                'usage': pynvml.nvmlDeviceGetPowerUsage(handle),
                'limit': pynvml.nvmlDeviceGetPowerManagementLimit(handle)
            }
        except pynvml.NVMLError_NotSupported:
            pass
        devices_full_status.append(full_status)
    status = {
        'basic': {
            'devices': devices_status
        },
        'full': {
            'devices': devices_full_status
        }
    }
    return status
