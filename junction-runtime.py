#!/usr/bin/env python3.12

import array
import os
import sys
import socket
import subprocess
import pty
import time
import ipaddress
import shlex

JUNCTION_PATH = "/users/friedj/junction"

from fcntl import flock, LOCK_EX, LOCK_NB
os.system("sudo touch /tmp/experiment_lock; sudo chmod 666 /tmp/experiment_lock")
fd = open("/tmp/experiment_lock", "w")
flock(fd.fileno(), LOCK_EX)

with open("/tmp/x.log", "a") as f:
	f.write(str(sys.argv))
	f.write("\n")

class Tee(object):
    def __init__(self, stdout, filename, mode="w"):
        self.file = open(filename, mode)
        self.stdout = stdout

    def write(self, message):
        self.file.write(message)
        self.stdout.write(message)

    def flush(self):
        self.file.flush()
        self.stdout.flush()

sys.stdout = Tee(sys.stdout, "/tmp/test_out", "a")
sys.stderr = Tee(sys.stderr, "/tmp/test_err", "a")

import json
import argparse

os.system("mkdir -p /tmp/containers/")
import requests_unixsocket

CGROUP_BASE = '/sys/fs/cgroup'

def create_cgroup(cgname):
    """Create a new cgroup and set resource limits."""
    cgroup_path = os.path.join(CGROUP_BASE, 'cpu', cgname)

    # Create cgroup directory if it doesn't exist
    if not os.path.exists(cgroup_path):
        os.makedirs(cgroup_path)

    # Set CPU limit (e.g., 50% of 1 CPU)
    # with open(os.path.join(cgroup_path, 'cpu.cfs_quota_us'), 'w') as f:
    #     f.write('50000')

    # # Set memory limit (e.g., 100 MB)
    # with open(os.path.join(cgroup_path, 'memory.limit_in_bytes'), 'w') as f:
    #     f.write(str(100 * 1024 * 1024))

    return cgroup_path

def assign_process_to_cgroup(pid, cgroup_path):
    """Add a process to the specified cgroup."""
    # Add the process to the cgroup by writing its PID to cgroup.procs
    with open(os.path.join(cgroup_path, 'cgroup.procs'), 'w') as f:
        f.write(str(pid))

def spawn_subprocess_with_fds(cfgpath, config, pty_sock):
    root = config["root"]["path"]
    envs = config["process"]["env"]

    arr = [f"{JUNCTION_PATH}/build/junction/junction_run", cfgpath, "--chroot", root]
    for env in envs:
        if env.startswith("LD_LIBRARY_PATH="):
            arr += ["--ld_path",  env.split("LD_LIBRARY_PATH=", 1)[1]]
        else:
            arr += ["-E", env]
    # arr += ["--interpreter_path", "--glibc_path"]
    arr += ["--uid", str(config["process"]["user"]["uid"])]
    arr += ["--gid", str(config["process"]["user"]["gid"])]

    cwd = config["process"].get("cwd", "/")
    if cwd != "/":
        arr += ["--cwd", cwd]

    arr.append("--")

    if pty_sock:
        master_fd, slave_fd = os.openpty()
        proc = subprocess.Popen(arr,
            stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
            close_fds=True,
            pass_fds=(slave_fd,)
        )
        os.close(slave_fd)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(pty_sock)
        sock.sendmsg([b'FD'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [master_fd]))])
        return proc

    for mdir in ["install", "bin"]:
        dstpath = f"{root}/{JUNCTION_PATH}/{mdir}"
        subprocess.check_call(shlex.split(f"sudo mkdir -p {dstpath}"))
        subprocess.check_call(shlex.split(f"sudo mount --bind -o ro {JUNCTION_PATH}/{mdir} {dstpath}"))

    for mount in config.get("mounts", []):
        if mount["type"] != "bind": continue
        op = "--rbind" if "rbind" in mount["options"] else "--bind"
        arg = "--make-rprivate" if "rprivate" in mount["options"] else ""

        if os.path.isfile(mount["source"]):
            subprocess.check_call(shlex.split(f"sudo touch {root}/{mount["destination"]}"))
        else:
            subprocess.check_call(shlex.split(f"sudo mkdir -p {root}/{mount["destination"]}"))
        cmd = f"sudo mount {op} {arg} {mount["source"]} {root}/{mount["destination"]}"
        subprocess.check_call(shlex.split(cmd))

    return subprocess.Popen(arr)

def get_container(container_id):
    pth = f"/tmp/containers/{container_id}"
    with open(f"{pth}/config.json") as f:
        return json.loads(f.read())

def do_ctl(ip, *args):
    args = " ".join(map(str, args))
    cmd = f"timeout 3 {JUNCTION_PATH}/build/junction-ctl/junction-ctl {ip} {args}"
    print("running", cmd)
    return os.system(f"timeout 3 {cmd} >> /tmp/xxlog 2>&1") == 0

def handle_create(args):
    ourpath = f"/tmp/containers/{args.container_id}"
    if os.system(f"mkdir -p {ourpath}") != 0:
        exit(-1)

    # Load the OCI config.json from the bundle directory
    config_path = os.path.join(args.bundle, 'config.json')
    with open(config_path, 'r') as f:
        config = json.load(f)

    with open(f"{ourpath}/config.json", "w") as f:
        f.write(json.dumps(config))

    os.system(f"ln -s {config["root"]["path"]} {ourpath}/root 2> /dev/null")

    os.system(f"touch {args.log}")

    ntw = None
    for i in range(3):
        networks = subprocess.check_output("docker network ls --format json", shell=True).decode("utf-8").splitlines()
        netnames = [json.loads(n)['Name'] for n in networks]
        dat = subprocess.check_output(f"docker network inspect {" ".join(netnames)}", shell=True)
        dat = json.loads(dat)
        for net in dat:
            if args.container_id in net["Containers"]:
                ntw = net["Containers"][args.container_id]['IPv4Address']
                break
        if ntw is not None:
            break
        time.sleep(2)
    if not ntw:
        print("failure...", args.container_id)
        exit(-1)
    network = ipaddress.IPv4Network(ntw, strict=False).netmask
    ipaddr = ipaddress.ip_interface(ntw).ip
    gateway = dat[0]["IPAM"]["Config"][0]["Gateway"]

    config["ip"] = str(ipaddr)

    with open(f"{ourpath}/caladan.config", "w") as f:
        f.write(f"host_addr {ipaddr}\n")
        f.write(f"host_netmask {network}\n")
        f.write(f"host_gateway {gateway}\n")
        f.write("runtime_kthreads 4\n")
        f.write("runtime_spinning_kthreads 0\n")
        f.write("runtime_guaranteed_kthreads 0\n")
        f.write("runtime_priority lc\n")
        f.write("runtime_quantum_us 0\n")

    cg = create_cgroup(config.get("cgroupsPath", args.container_id))

    proc = spawn_subprocess_with_fds(f"{ourpath}/caladan.config", config, args.console_socket)

    assign_process_to_cgroup(proc.pid, cg)

    with open(args.pid_file, 'w') as f:
        f.write(str(proc.pid))

    config["pid"] = str(proc.pid)
    with open(f"{ourpath}/config.json", "w") as f:
        f.write(json.dumps(config))

    # xx
    # for hook in config.get("hooks", {}).get("prestart", []):
        # do_ctl(config["ip"], "run_aux", hook["path"], *hook["args"])

def handle_start(args):
    config = get_container(args.container_id)

    path = None
    for env in config["process"]["env"]:
        if not env.startswith("PATH="): continue
        env = env.split("PATH=", 1)[1]
        path = env.split(":")

    args = config["process"]["args"]

    root = config["root"]["path"]

    for i in range(1, len(args)):
        if len(args[i]) and args[i][0] == '-':
            args[i] = f'-- {args[i]}'
        else:
            args[i] = f'{args[i]}'

    if args[0][0] != "/" and path:
        for prefix in path:
            if not os.path.exists(f"{root}/{prefix}/{args[0]}"):
                continue

            if do_ctl(config["ip"], "run", f"{prefix}/{args[0]}", *args[1:]):
                return

    if not do_ctl(config["ip"], "run", *config["process"]["args"]):
        exit(-1)

def handle_delete(args):
    container_id = args.container_id
    force_delete = '--force' in args

    try:
        config = get_container(args.container_id)
    except:
        exit(0)
    if "pid" in config:
        os.system(f"kill -9 {config["pid"]}")

    root = config["root"]["path"]
    for mount in config.get("mounts", []):
        if mount["type"] != "bind": continue
        os.system(f"sudo umount {root}/{mount["destination"]}")

    for mdir in ["install", "bin"]:
        dstpath = f"{root}/{JUNCTION_PATH}/{mdir}"
        os.system(f"sudo umount {JUNCTION_PATH}/{mdir} {dstpath}")

    print(f"Deleting container {container_id}, force: {force_delete}")
    if os.system(f"rm -rf /tmp/containers/{args.container_id}") != 0:
         exit(-1)

def handle_kill(args):
    config = get_container(args.container_id)
    # do_ctl(config["ip"], "signal", 1, "SIGKILL")
    if "pid" in config:
        os.system(f"kill -9 {config["pid"]}")

def handle_exec(args):
    config = get_container(args.container_id)
    do_ctl(config["ip"], "signal", 1, "SIGKILL")


features = """{
    "ociVersionMin": "1.0.0",
    "ociVersionMax": "1.0.2-dev",
    "hooks": [
        "prestart",
        "createRuntime",
        "createContainer",
        "startContainer",
        "poststart",
        "poststop"
    ],
    "mountOptions": [
        "acl",
        "async",
        "atime",
        "bind",
        "defaults",
        "dev",
        "diratime",
        "dirsync",
        "exec",
        "iversion",
        "lazytime",
        "loud",
        "mand",
        "noacl",
        "noatime",
        "nodev",
        "nodiratime",
        "noexec",
        "noiversion",
        "nolazytime",
        "nomand",
        "norelatime",
        "nostrictatime",
        "nosuid",
        "nosymfollow",
        "private",
        "ratime",
        "rbind",
        "rdev",
        "rdiratime",
        "relatime",
        "remount",
        "rexec",
        "rnoatime",
        "rnodev",
        "rnodiratime",
        "rnoexec",
        "rnorelatime",
        "rnostrictatime",
        "rnosuid",
        "rnosymfollow",
        "ro",
        "rprivate",
        "rrelatime",
        "rro",
        "rrw",
        "rshared",
        "rslave",
        "rstrictatime",
        "rsuid",
        "rsymfollow",
        "runbindable",
        "rw",
        "shared",
        "silent",
        "slave",
        "strictatime",
        "suid",
        "symfollow",
        "sync",
        "tmpcopyup",
        "unbindable"
    ],
    "linux": {
        "namespaces": [
            "cgroup",
            "ipc",
            "mount",
            "network",
            "pid",
            "user",
            "uts"
        ],
        "capabilities": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
        ],
        "cgroup": {
            "v1": true,
            "v2": true,
            "systemd": true,
            "systemdUser": true
        },
        "seccomp": {
            "enabled": true,
            "actions": [
                "SCMP_ACT_ALLOW",
                "SCMP_ACT_ERRNO",
                "SCMP_ACT_KILL",
                "SCMP_ACT_KILL_PROCESS",
                "SCMP_ACT_KILL_THREAD",
                "SCMP_ACT_LOG",
                "SCMP_ACT_NOTIFY",
                "SCMP_ACT_TRACE",
                "SCMP_ACT_TRAP"
            ],
            "operators": [
                "SCMP_CMP_EQ",
                "SCMP_CMP_GE",
                "SCMP_CMP_GT",
                "SCMP_CMP_LE",
                "SCMP_CMP_LT",
                "SCMP_CMP_MASKED_EQ",
                "SCMP_CMP_NE"
            ],
            "archs": [
                "SCMP_ARCH_AARCH64",
                "SCMP_ARCH_ARM",
                "SCMP_ARCH_MIPS",
                "SCMP_ARCH_MIPS64",
                "SCMP_ARCH_MIPS64N32",
                "SCMP_ARCH_MIPSEL",
                "SCMP_ARCH_MIPSEL64",
                "SCMP_ARCH_MIPSEL64N32",
                "SCMP_ARCH_PPC",
                "SCMP_ARCH_PPC64",
                "SCMP_ARCH_PPC64LE",
                "SCMP_ARCH_RISCV64",
                "SCMP_ARCH_S390",
                "SCMP_ARCH_S390X",
                "SCMP_ARCH_X32",
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X86_64"
            ]
        },
        "apparmor": {
            "enabled": true
        },
        "selinux": {
            "enabled": true
        }
    },
    "annotations": {
        "io.github.seccomp.libseccomp.version": "2.5.3",
        "org.opencontainers.runc.checkpoint.enabled": "true",
        "org.opencontainers.runc.commit": "v1.1.14-0-g2c9f560",
        "org.opencontainers.runc.version": "1.1.14"
    }
}"""


def main():
    parser = argparse.ArgumentParser(description="Custom OCI Runtime")

    # Define the optional arguments first
    parser.add_argument('--root', required=False, help='Root path for the runtime')
    parser.add_argument('--log', required=False, help='Log file path')
    parser.add_argument('--log-format', choices=['json', 'text'], required=False, help='Log format (json or text)')

    # Add a positional argument for the command (create, delete, etc.)
    parser.add_argument('command', choices=['create', 'delete', 'start', 'kill', 'exec', 'features'], help='The command to execute')

    # Common arguments for all commands
    parser.add_argument('container_id', help='ID of the container')

    # Additional arguments for `create`
    parser.add_argument('--bundle', help='Path to the bundle directory (required for create)')
    parser.add_argument('--pid-file', help='Path to write the PID file (required for create)')
    parser.add_argument('--console-socket', help='Path to the console socket (required for create)')

    parser.add_argument('--systemd-cgroup', action='store_true')
    parser.add_argument('--all', action='store_true')

    # Additional arguments for `delete`
    parser.add_argument('--force', action='store_true', help='Force delete the container')

    # Parse the arguments
    args, unknown = parser.parse_known_args()

    # Dispatch to the correct handler based on the command
    if args.command == 'create':
        handle_create(args)
    elif args.command == 'delete':
        handle_delete(args)
    elif args.command == 'start':
        handle_start(args)
    elif args.command == 'kill':
        handle_kill(args)
    elif args.command == 'exec':
        handle_exec(args)
    elif args.command == 'features':
        print(features)
    else:
        print("Unknown command")
        sys.exit(1)

if __name__ == "__main__":
    main()
