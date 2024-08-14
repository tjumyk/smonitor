import os.path
import threading
from functools import wraps
from typing import Optional

_DEFAULT_DRIVER_PATH = '/usr/local/Ascend'

_load_lock = threading.Lock()
_loaded_device_indices = set()
_is_loaded = False


class ACLError(Exception):
    pass


class ACLDeviceUtilizationRate:
    def __init__(self, cube: float, vector: float, aicpu: float):
        self.cube = cube
        self.vector = vector
        self.aicpu = aicpu


class ACLDeviceMemoryInfo:
    def __init__(self, free: int, total: int):
        self.free = free
        self.total = total


def ensure_loaded(f):
    @wraps
    def wrapped(*args, **kwargs):
        if not _is_loaded:
            raise ACLError('acl is not yet initialized')
        return f(*args, **kwargs)

    return wrapped


def acl_init():
    global _is_loaded

    try:
        import acl
    except ImportError as e:
        raise ACLError('failed to import acl package') from e

    with _load_lock:
        if not _is_loaded:
            try:
                ret = acl.init()
            except Exception as e:
                raise ACLError('failed to init acl package') from e
            if not isinstance(ret, (int, float)) or ret != 0:
                raise ACLError('failed to init acl package (ret=%s)' % ret)
            _is_loaded = True


def acl_shutdown():
    global _is_loaded

    with _load_lock:
        if _is_loaded:
            for _device_index in _loaded_device_indices:
                _reset_device(_device_index)
            try:
                ret = acl.finalize()
            except Exception as e:
                raise ACLError('failed to finalize acl package') from e
            if not isinstance(ret, (int, float)) or ret != 0:
                raise ACLError('failed to finalize acl package (ret=%s)' % ret)
            _is_loaded = False


def get_driver_version() -> Optional[str]:
    version_path = os.path.join(_DEFAULT_DRIVER_PATH, 'version.info')
    if not os.path.exists(version_path):
        return None
    with open(version_path) as f_in:
        version_info = f_in.read().strip()
    if version_info.startswith('version='):
        return version_info.split('=', maxsplit=1)[1]
    return None


@ensure_loaded
def get_acl_version() -> str:
    try:
        major, minor, patch, ret = acl.get_version()
    except Exception as e:
        raise ACLError('failed to get acl version: %s' % str(e))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to get acl version (ret=%s)' % ret)
    return '.'.join([str(x) for x in (major, minor, patch)])


@ensure_loaded
def get_device_count() -> int:
    try:
        count, ret = acl.rt.get_device_count()
    except Exception as e:
        raise ACLError('failed to get device count: %s' % str(e))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to get device count (ret=%r)' % ret)
    if not isinstance(count, int) or count < 0:
        raise ACLError('obtained invalid device count: %r' % count)
    return count


def _reset_device(device_index: int):
    try:
        ret = acl.rt.reset_device(device_index)
    except Exception as e:
        raise ACLError('failed to reset device %r: %s' % (device_index, str(e)))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to reset device %r (ret=%r)' % (device_index, ret))


@ensure_loaded
def get_device_name(device_index: int) -> str:
    try:
        name = acl.get_soc_name(device_index)
    except Exception as e:
        raise ACLError('failed to get name of device %r: %s' % (device_index, str(e)))
    return name


@ensure_loaded
def get_device_memory_info(device_index: int) -> ACLDeviceMemoryInfo:
    try:
        ret = acl.rt.set_device(device_index)
    except Exception as e:
        raise ACLError('failed to set device to %r: %s' % (device_index, str(e)))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to set device to %r (ret=%r)' % (device_index, ret))

    try:
        free, total, ret = acl.rt.get_mem_info(0)
    except Exception as e:
        raise ACLError('failed to get memory info of device %r: %s' % (device_index, str(e)))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to get memory info of device %r (ret=%r)' % (device_index, ret))

    info = ACLDeviceMemoryInfo(free=free, total=total)
    return info


@ensure_loaded
def get_device_utilization_rates(device_index: int) -> ACLDeviceUtilizationRate:
    try:
        data, ret = acl.rt.get_device_utilization_rate(device_index)
    except Exception as e:
        raise ACLError('failed to get utilization rate of device %r: %s' % (device_index, str(e)))
    if not isinstance(ret, (int, float)) or ret != 0:
        raise ACLError('failed to get utilization rate of device %r (ret=%r)' % (device_index, ret))
    rate = ACLDeviceUtilizationRate(
        cube=data['cube_utilization'],
        vector=data['vector_utilization'],
        aicpu=data['aicpu_utilization']
    )
    return rate


@ensure_loaded
def get_running_processes(handle):
    raise NotImplementedError()
