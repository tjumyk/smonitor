import getpass
import os
import sys


def _generate_conf(name, user, command, work_dir, auto_start, auto_restart):
    conf = "[program:%s]" % name
    conf += "\nuser=%s" % user
    conf += "\ncommand=%s" % command
    conf += "\ndirectory=%s" % work_dir
    conf += "\nautostart=%s" % ("true" if auto_start else "false")
    conf += "\nautorestart=%s" % ("true" if auto_restart else "false")
    conf += "\n"
    return conf


def generate_main_conf():
    user = getpass.getuser()
    python = sys.executable
    script = 'smonitor.py'
    command = "%s %s" % (python, script)
    work_dir = os.getcwd()
    return _generate_conf('smonitor', user, command, work_dir, True, True)


def generate_manager_conf():
    user = 'root'
    python = sys.executable
    script = 'manager.py'
    command = "%s %s" % (python, script)
    work_dir = os.getcwd()
    return _generate_conf('smonitor-manager', user, command, work_dir, True, True)


if __name__ == '__main__':
    output_dir = 'supervisor-conf'
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    with open(os.path.join(output_dir, 'smonitor.conf'), 'w') as f:
        f.write(generate_main_conf())
    with open(os.path.join(output_dir, 'smonitor-manager.conf'), 'w') as f:
        f.write(generate_manager_conf())
