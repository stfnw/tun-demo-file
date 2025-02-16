# What is this

A demo of userspace-networking / TUN devices on Linux.
This allows us to implement our own network access layer that plugs into the usual Linux kernel network stack, so that it can be used for arbitrary network communication.
Here specifically, we open a network tunnel over the file system, assuming e.g. a shared folder between VMs.

# Usage

Specify `--help` or [see the source code in the parse_args function](tun-tunnel-fs.py#L26):

```
$ python3 tun-tunnel-fs.py --help
usage: tun-tunnel-fs [-h] (--server | --client) [--ifname IFNAME] --ip IP --dirpath DIRPATH [-v]

Demo project tunneling network traffic over the filesystem as physical layer (using a TUN device).

options:
  -h, --help         show this help message and exit
  --server           Run in server mode
  --client           Run in client mode
  --ifname IFNAME    TUN: Name of the tun interface that should be created
  --ip IP            TUN: IP address of this program instance in CIDR notation (example: 192.0.2.1/24)
  --dirpath DIRPATH  FS: path to the directory that should be used for the actual data exchange as physical layer
  -v, --verbose
```

It needs to be started with root permissions for creating the tun network interface and assigning IP addresses to it.
[See demo](#demo) for a specific example.
Exit the program with CTRL-C.

Python dependencies: none.
Non-python dependencies:

- `ip` binary from the iproute2 package:

- `iptables` binary from the iptables package:

```
sudo apt install iproute2 iptables
```

# Demo

Setup: two VMs:
- `A` without internet (will be configured in "client" mode)
- `B` with internet (will be configured in "server" mode)

In this demo we share the internet of VM `B` with the VM `A` through the TUN tunnel created by this program.


https://github.com/user-attachments/assets/1b2357d7-f5fd-4ee5-8617-e04737064737


On VM `A`: this will create a new network interface `tun0`, assign it the IP address 192.0.2.2/24 and set the default route of the system to be over this interface.
For transferring the actual data, files in the shared folder that is mounted at `/share` will be used.

```
sudo python3 tun-tunnel-fs.py --client --ifname tun0 --ip 192.0.2.2/24 --dirpath /share/ -v
```

On VM `B`: this will create a new network interface `tun0`, assign it the IP address 192.0.2.1/24 and set up IP forwarding and masquerading/NAT to automatically route incoming network traffic.
For transferring the actual data, files in the shared folder that is mounted at `/share` will be used.

```
sudo python3 tun-tunnel-fs.py --server --ifname tun0 --ip 192.0.2.1/24 --dirpath /share/ -v
```

<!--

A and B:
    tmux
    ip address show
    ip route show
    ping -c2 kernel.org

A:
    watch -n1 ls /share
    sudo python3 tun-tunnel-fs.py --client --ifname tun0 --ip 192.0.2.2/24 --dirpath /share/ -v

B:
    sudo python3 tun-tunnel-fs.py --server --ifname tun0 --ip 192.0.2.1/24 --dirpath /share/ -v

A and B:
    ip address show
    ip route show

A:
    dig kernel.org
    ping -c2 kernel.org
    curl http://google.com

A: (restart in non-verbose mode)
    sudo python3 tun-tunnel-fs.py --client --ifname tun0 --ip 192.0.2.2/24 --dirpath /share/

B: (restart in non-verbose mode)
    sudo python3 tun-tunnel-fs.py --server --ifname tun0 --ip 192.0.2.1/24 --dirpath /share/

A: browse to kernel.org
    firefox

-->

# References:

- https://docs.kernel.org/networking/tuntap.html#network-device-allocation
- https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/
- https://backreference.org/2010/03/26/tuntap-interface-tutorial/index.html (GPLv3 -> this project is also GPLv3)
