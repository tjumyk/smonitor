import os
import json
from collections import defaultdict


def get_user_hosts(canonical_uid: str) -> dict:
    map_file_path = os.path.join('user_hosts', canonical_uid + '.json')
    return _read_user_hosts_map(map_file_path)


def update_user_host(canonical_uid: str, host: str, user_name: str):
    # FIXME thread-unsafe
    map_file_path = os.path.join('user_hosts', canonical_uid + '.json')
    mapping = _read_user_hosts_map(map_file_path)
    mapping[host] = user_name
    _write_user_hosts_map(map_file_path, mapping)


def _read_user_hosts_map(map_file_path: str) -> dict:
    if not os.path.exists(map_file_path):
        return {}
    mapping = {}
    with open(map_file_path) as f:
        for name, hosts in json.load(f).items():
            for host in hosts:
                mapping[host] = name
    return mapping


def _write_user_hosts_map(map_file_path: str, mapping: dict):
    dirname = os.path.dirname(map_file_path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    name_hosts_dict = defaultdict(list)
    for host, name in mapping.items():
        name_hosts_dict[name].append(host)
    with open(map_file_path, 'w') as f:
        json.dump(name_hosts_dict, f)
