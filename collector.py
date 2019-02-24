import platform
import sys
import threading
from collections import defaultdict

import distro
import psutil
from cpuinfo import cpuinfo

import loggers
import pynvml
import repository

GLOBAL_ACTIVE_USER = '*'

logger = loggers.get_logger(__name__)

_nvml_inited = False
_static_info = {
    'public': {},
    'private': {}
}
_process_info = {}
_process_info_lock = threading.Lock()


def init():
    global _nvml_inited
    _update_package_info()
    _update_platform_info()
    _update_psutil_static_info()
    try:
        pynvml.nvmlInit()
        _nvml_inited = True
        logger.info('[NVML] NVML Initialized')
        _update_nvml_static_info()
    except pynvml.NVMLError as e:
        logger.warning('[NVML] NVML Not Initialized: %s' % str(e))
        pass


def clean_up():
    global _nvml_inited
    if _nvml_inited:
        try:
            pynvml.nvmlShutdown()
            logger.info('[NVML] NVML Shutdown')
        except pynvml.NVMLError as e:
            logger.error('[NVML] NVML Failed to Shutdown: %s' % str(e))
            pass
    _nvml_inited = False
    _static_info['public'] = {}
    _static_info['private'] = {}


def get_static_info():
    return _static_info['public'].copy()


def get_status(active_users: set = None):
    """
    Get host status
    :param active_users: If active_users is None or empty, it returns basic info only. Otherwise, it returns full info
                         according to the members of active_users.
    :return: A dictionary of status info
    """
    status = _get_status_psutil(active_users)
    if _nvml_inited:
        status_nvml = _get_status_nvml(active_users)

        # Merge basic GPU info
        status['basic']['gpu'] = status_nvml['basic']

        # Merge full GPU info
        full_status = status.get('full')
        full_nvml_status = status_nvml.get('full')
        if full_status and full_nvml_status:
            full_status['gpu'] = full_nvml_status

        # Merge personal GPU info
        personal_status = status.get('personal')
        personal_nvml_status = status_nvml.get('personal')
        if personal_status and personal_nvml_status:
            for user, _status in personal_status.items():
                _status_nvml = personal_nvml_status.get(user)
                if _status_nvml:
                    _status['gpu'] = _status_nvml
    return status


def _update_package_info():
    try:
        _static_info['public']['package'] = {
            "label": repository.get_head()
        }
    except Exception as e:
        logger.error('Failed to get the package information: %s' % str(e))


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
    elif system == 'Windows':
        win_version = sys.getwindowsversion()
        if win_version.minor:
            version = "%d.%d" % (win_version.major, win_version.minor)
        else:
            version = str(win_version.major)
        info['distribution'] = {
            'name': 'Windows',
            'version': version
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
        if 'cdrom' in part.opts.split(','):  # skip CD-ROMs (but possibly a bug in psutil)
            continue
        if part.device.startswith('/dev/loop'):  # skip loop devices
            continue
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
    system = platform.system()
    for name, device in partitions.items():
        mount_points = device['mount_points']
        usage = psutil.disk_usage(mount_points[0])
        if system == 'Linux':
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
        elif system == 'Windows':
            if 'C:\\' in mount_points:  # FIXME find a better way to decide if it is the system partition
                sys_partition = {'total': usage.total}
                device['category'] = 'system'
                _static_info['private']['disk']['system'] = device
            else:
                other_partitions_total += usage.total
                device['category'] = 'others'
                _static_info['private']['disk']['others'].append(device)
        else:  # FIXME find system partition for MacOS or others
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


def _get_status_psutil(active_users):
    if active_users:
        require_global_detail = GLOBAL_ACTIVE_USER in active_users
        collect_personal_for_users = active_users - {GLOBAL_ACTIVE_USER}
    else:
        require_global_detail = False
        collect_personal_for_users = set()

    # Memory
    vm = psutil.virtual_memory()

    # Disk
    sys_partition = None
    boot_partition = None
    sys_device = _static_info['private']['disk'].get('system')
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
        if sys_device is not None and name == sys_device['name']:
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
        }
    }
    if active_users:
        personal_process_lists = defaultdict(list)

        # Process
        with _process_info_lock:
            _process_info.clear()
            for p in psutil.process_iter(attrs=['pid', 'name', 'username', 'cmdline', 'ppid', 'status',
                                                'cpu_times', 'cpu_percent',
                                                'memory_info', 'memory_percent']):
                info = p.info
                cpu_time_info = info['cpu_times']
                mem_info = info['memory_info']
                info['cpu_times'] = {
                    'total': round(100 * (cpu_time_info.user + cpu_time_info.system)) / 100
                }
                mem_info_dict = {'rss': mem_info.rss, 'vms': mem_info.vms}
                if hasattr(mem_info, 'shared'):
                    mem_info_dict['shared'] = mem_info.shared
                info['memory_info'] = mem_info_dict
                info['memory_percent'] = round(info['memory_percent'] * 10) / 10
                _process_info[info['pid']] = info

                username = info['username']
                if username in collect_personal_for_users:
                    personal_process_lists[username].append(info)

        # Memory
        swap = psutil.swap_memory()

        if require_global_detail:
            top_cpu_processes = sorted(filter(lambda v: v['cpu_percent'] > 0, _process_info.values()),
                                       key=lambda v: v['cpu_percent'], reverse=True)[:30]
            top_mem_processes = sorted(filter(lambda v: v['memory_percent'] > 0, _process_info.values()),
                                       key=lambda v: v['memory_percent'], reverse=True)[:30]
            memory_status = {
                'available': vm.available,
                'used': vm.used,
                'free': vm.free,
                'used_percent': round(1000 * vm.used / vm.total) / 10,
                'free_percent': round(1000 * vm.free / vm.total) / 10,
                'top_processes': top_mem_processes
            }
            if platform.system() == 'Linux':
                memory_status['buffers'] = vm.buffers
                memory_status['cached'] = vm.cached
                memory_status['buffers_percent'] = round(1000 * vm.buffers / vm.total) / 10
                memory_status['cached_percent'] = round(1000 * vm.cached / vm.total) / 10

            status['full'] = {
                'cpu': {
                    'percents': psutil.cpu_percent(percpu=True),
                    'top_processes': top_cpu_processes
                },
                'memory': memory_status,
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

        if collect_personal_for_users:
            personal_status = defaultdict(dict)

            for user, process_list in personal_process_lists.items():
                personal_status[user]['top_processes'] = \
                    sorted(process_list, key=lambda v: v['cpu_percent'], reverse=True)[:30]

            status['personal'] = personal_status
    return status


def _get_status_nvml(active_users):
    if active_users:
        require_global_detail = GLOBAL_ACTIVE_USER in active_users
        collect_personal_for_users = active_users - {GLOBAL_ACTIVE_USER}
    else:
        require_global_detail = False
        collect_personal_for_users = set()

    devices_status = []
    devices_full_status = []
    devices_personal_status = defaultdict(dict)
    for gpu_index, handle in enumerate(_static_info['private']['gpu']['handles']):
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

        if active_users:
            process_users = set()
            process_list = []
            with _process_info_lock:
                for p in process_info:
                    info = _process_info[p.pid]
                    info['gpu_memory'] = p.usedGpuMemory  # add gpu_memory field as it is only provided by NVML
                    process_users.add(info['username'])
                    process_list.append(info)

            process_list.sort(key=lambda i: i['gpu_memory'] or 0, reverse=True)
            requesting_users = set.intersection(process_users, collect_personal_for_users)

            if require_global_detail or requesting_users:
                full_status = {
                    'memory': {
                        'free': mem_info.free,
                        'used': mem_info.used
                    },
                    'process_list': process_list
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

                if require_global_detail:
                    devices_full_status.append(full_status)
                for user in requesting_users:
                    devices_personal_status[user][gpu_index] = full_status

    status = {
        'basic': {
            'devices': devices_status
        }
    }

    if require_global_detail:
        status['full'] = {
            'devices': devices_full_status
        }

    if collect_personal_for_users:
        status['personal'] = {user: {'devices': status} for user, status in devices_personal_status.items()}
    return status
