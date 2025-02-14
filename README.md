# What is this

A *Demo* of userspace-networking / TUN devices on Linux.
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

TODO

# References:

- https://docs.kernel.org/networking/tuntap.html#network-device-allocation
- https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/
- https://backreference.org/2010/03/26/tuntap-interface-tutorial/index.html (GPLv3 -> this project is also GPLv3)
