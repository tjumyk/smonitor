import os
import json


def get_user_hosts(canonical_uid: str) -> dict:
    map_file_path = os.path.join('user_hosts', canonical_uid + '.json')
    return _read_user_hosts_map(map_file_path)


def update_user_host(canonical_uid: str, host: str, user_info: dict):
    # FIXME thread-unsafe
    map_file_path = os.path.join('user_hosts', canonical_uid + '.json')
    mapping = _read_user_hosts_map(map_file_path)
    mapping[host] = user_info
    _write_user_hosts_map(map_file_path, mapping)


def _read_user_hosts_map(map_file_path: str) -> dict:
    if not os.path.exists(map_file_path):
        return {}
    with open(map_file_path) as f:
        return json.load(f)


def _write_user_hosts_map(map_file_path: str, mapping: dict):
    dirname = os.path.dirname(map_file_path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    with open(map_file_path, 'w') as f:
        json.dump(mapping, f)
