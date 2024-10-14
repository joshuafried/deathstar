#!/bin/bash

set -e
set -x

: <<'EOF'

## Recommend using Ubuntu 24.04 (need python3.12 at the moment)
# Setting up Junction notes:
 1. Clone juntion: git clone -b dev https://github.com/JunctionOS/junction
 2. Install and build (scripts/install.sh; scripts/build.sh) - make sure rust is installed (see README)
 3a. Configure Mellanox NIC for SR-IOV and setup e-switch using `lib/caladan/scripts/setup_vfs.sh <interface_name>`. Note the interface name and PCI address printed.
 4a. Run the iokernel using `sudo lib/caladan/iokerneld ias vfio nicpci <VF pci output in previous step> numanode <numa node with nic>

 3a. No mellanox NIC: run the iokernel with a tap device: `sudo lib/caladan/iokerneld ias no_hw_qdel numanode <numa node with nic> -- --allow 00:00.0 --vdev=net_tap0`

# Set up docker
 1. Follow instructions online to install docker (https://docs.docker.com/engine/install/ubuntu/)
 2. Set up custom runtime - add to /etc/docker/daemon.json:
{
  "runtimes": {
    "junction": {
      "path": "<path_to_deathstar>/junction-runtime.py"
    }
  }
}
 3. Make sure you have installed the requests_unixsocket python package (sudo apt install python3-requests-unixsocket)
 4. Restart docker

# Set up deathstar
 1. Run the setup.sh script in socialNetwork/
 2. Join the iokernel network to the socialNetwork bridge:
    - Check the network ID of the socialnet network using `docker network ls` (ie 600ec8f8f4b8)
    - Add the corresponding interface as a member of that bridge: `sudo ip link set dev <interface name> master br-<network id>`
       - If you are using a Mellanox NIC, the interface name was printed in step 3a during Junction setup.
       - If you are using the TAP device, the device name should be dtap0

## Now run an experiment using the commands below
EOF
#

# Confine Linux processing to the other NUMA node (verify with lscpu)
# TODO: confine interrupts too
export LINUX_CPU_SET=0-31,64-95

export SERVICE_RUNTIME=junction
export SERVICE_RUNTIME_MEMCACHED=junction
export SERVICE_RUNTIME_REDIS=junction

# export SERVICE_RUNTIME=runc
# export SERVICE_RUNTIME_MEMCACHED=runc
# export SERVICE_RUNTIME_REDIS=runc

docker compose down

docker compose up -d || (sleep 2; docker compose up -d || (sleep 2; docker compose up -d))

sleep 30

python3 scripts/init_social_graph.py --graph=socfb-Reed98 --ip 172.32.0.30

# taskset -c $LINUX_CPU_SET ../wrk2/wrk -D exp -t 12 -c 400 -d 30 -L -s ./wrk2/scripts/social-network/read-home-timeline.lua http://172.32.0.30:8080/wrk2-api/home-timeline/read -R 1000
taskset -c $LINUX_CPU_SET ../wrk2/wrk -D exp -t 12 -c 400 -d 30 -L -s ./wrk2/scripts/social-network/read-user-timeline.lua http://172.32.0.30:8080/wrk2-api/user-timeline/read -R 2000
# taskset -c $LINUX_CPU_SET ../wrk2/wrk -D exp -t 12 -c 400 -d 300 -L -s ./wrk2/scripts/social-network/compose-post.lua http://172.32.0.30:8080/wrk2-api/post/compose -R 1000

