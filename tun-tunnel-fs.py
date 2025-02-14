#!/usr/bin/python3


from dataclasses import dataclass
from fcntl import ioctl
import argparse
import asyncio
import logging
import os
import signal
import struct
import subprocess
import threading
import time
import types
import typing


def runcmd(
    cmd: list[str], check: bool = True, capture_output: bool = False
) -> typing.Any:
    logging.info("Running command: %s", str(cmd))
    return subprocess.run(cmd, check=check, capture_output=capture_output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tun-tunnel-fs",
        description="Demo project tunneling network traffic over the filesystem as physical layer (using a TUN device).",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--server", action="store_true", dest="server", help="Run in server mode"
    )
    group.add_argument(
        "--client", action="store_false", dest="server", help="Run in client mode"
    )

    parser.add_argument(
        "--ifname",
        help="TUN: Name of the tun interface that should be created",
        default="tun0",
    )

    parser.add_argument(
        "--ip",
        help="TUN: IP address of this program instance in CIDR notation (example: 192.0.2.1/24)",
        required=True,
    )

    parser.add_argument(
        "--dirpath",
        help="FS: path to the directory that should be used for the actual data exchange as physical layer",
        required=True,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO,
        dest="loglevel",
    )

    args = parser.parse_args()

    logging.basicConfig(
        encoding="utf8",
        level=args.loglevel,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not os.path.isdir(args.dirpath):
        logging.info(
            'Specified directory path "%s" doesn\'t exist. Creating it...', args.dirpath
        )

    if (
        runcmd(
            ["ip", "link", "show", "dev", args.ifname], check=False, capture_output=True
        ).returncode
        == 0
    ):
        parser.error(
            f"Specified tun interface name {args.ifname} already exists. "
            + "In case it is a left-over from a previous run of this program (this shouldn't usually happen), "
            + "it can be deleted with \n\n    sudo ip link delete tun0\n\n"
            + "Otherwise, specify another interface name."
        )

    return args


# Used for capturing and restoring the network configuration of the system
# before starting this program.
@dataclass
class NetConfig:
    ip_forward: str  # state of /proc/sys/net/ipv4/ip_forward
    default_route: str


def get_netconfig() -> NetConfig:
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        ip_forward = f.read()
    default_route = (
        runcmd("ip route show default".split(), capture_output=True)
        .stdout.decode("utf8")
        .strip()
    )
    return NetConfig(ip_forward, default_route)


def tun_teardown(ifname: str, server: bool, ipcidr: str, netconfig: NetConfig) -> None:
    if server:
        logging.info("Restoring ip_forward to %s", netconfig.ip_forward.strip())
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(netconfig.ip_forward)
        # fmt: off
        runcmd(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ipcidr, "-j", "MASQUERADE"])
        runcmd(["iptables", "-D", "FORWARD", "-i", ifname, "-s", ipcidr, "-j", "ACCEPT"])
        runcmd(["iptables", "-D", "FORWARD", "-o", ifname, "-d", ipcidr, "-j", "ACCEPT"])
        # fmt: on
    else:
        if netconfig.default_route != "":
            runcmd(["ip", "route", "replace"] + netconfig.default_route.split())

    runcmd(["ip", "link", "delete", "dev", ifname])


def signal_handler(
    name: str, server: bool, ipcidr: str, netconfig: NetConfig
) -> typing.Any:
    def handler(_sig: int, _frame: types.FrameType) -> None:
        print()
        logging.info("You pressed Ctrl+C! Cleaning up and exiting...")
        stop_event.set()
        for task in asyncio.all_tasks():
            task.cancel()
        tun_teardown(name, server, ipcidr, netconfig)

    return handler


def tun_setup(ifname: str, ipcidr: str, server: bool) -> typing.IO[bytes]:
    ip = ipcidr.split("/")[0]

    runcmd(["ip", "tuntap", "add", "name", ifname, "mode", "tun"])
    runcmd(["ip", "addr", "add", ipcidr, "broadcast", "+", "dev", ifname])
    runcmd(["ip", "link", "set", "dev", ifname, "up"])

    if server:
        logging.info("Setting ip_forward to 1")
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        # fmt: off
        runcmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ipcidr, "-j", "MASQUERADE"])
        runcmd(["iptables", "-A", "FORWARD", "-i", ifname, "-s", ipcidr, "-j", "ACCEPT"])
        runcmd(["iptables", "-A", "FORWARD", "-o", ifname, "-d", ipcidr, "-j", "ACCEPT"])
        # fmt: on
    else:
        runcmd(["ip", "route", "replace", "default", "via", ip, "dev", ifname])

    print()

    tun = open("/dev/net/tun", "r+b", buffering=0)
    # see linux/if.h and linux/if_tun.h
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifreq = struct.pack("16sH22s", ifname.encode("utf8"), flags, b"")  # struct ifreq
    ioctl(tun, LINUX_TUNSETIFF, ifreq)

    return tun


def isprintable(c: int) -> bool:
    return 0x20 <= c and c <= 0x7E


def hexdump(bs: bytes) -> str:
    res: list[str] = []
    chunksize = 0x10
    chunks = [bs[i : i + chunksize] for i in range(0, len(bs), chunksize)]
    for chunk in chunks:
        res += "    "
        for i in range(chunksize):
            if i < len(chunk):
                res += f"{chunk[i]:02x} "
            else:
                res += "   "
        res += "    "
        for b in chunk:
            res += chr(b) if isprintable(b) else "."
        res += "\n"
    return "".join(res)


def getfilename(s: str) -> str:
    return "".join((c if c.isalnum() else "-") for c in s)


# Note: since one of the two transport ways (tun / fs) is not a file descriptor,
# we can't just use poll for both. We could use poll for tun and not for the fs,
# but here I just wrapped both coroutines into their own threads and directly
# used the blocking functions, even for the tun device. The filesystem part of
# the communication is simply done synchronously, because it shouldn't take
# that long.

MAX_SIZE = 0x10000

stop_event = threading.Event()


async def from_tun(dirpath: str, ipcidr: str, tun: typing.IO[bytes]) -> None:
    loop = asyncio.get_event_loop()

    while not stop_event.is_set():
        buf = await loop.run_in_executor(None, tun.read, MAX_SIZE)

        logging.info("From TUN: received %10d bytes", len(buf))
        logging.debug("Hexdump:\n%s", hexdump(buf))

        filename = getfilename(ipcidr) + "-" + str(time.time_ns())
        with open(os.path.join(dirpath, "_" + filename), "wb") as f:
            f.write(buf)
        # Write-then-rename to hopefully make sure that the receiving side
        # always sees either no new data, or *all* new data (no partial reads).
        os.rename(
            os.path.join(dirpath, "_" + filename), os.path.join(dirpath, filename)
        )


async def from_fs(dirpath: str, ipcidr: str, tun: typing.IO[bytes]) -> None:
    loop = asyncio.get_event_loop()

    while not stop_event.is_set():
        files = [
            f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath, f))
        ]
        for file in files:
            if file.startswith(getfilename(ipcidr)):
                # Ignore own data / data written by this program instance.
                continue
            if file.startswith("_"):
                # Ignore temporary files.
                continue
            with open(os.path.join(dirpath, file), "rb") as f:
                buf = f.read()

                logging.info("From FS:  received %10d bytes", len(buf))
                logging.debug("Hexdump:\n%s", hexdump(buf))

                if len(buf) >= MAX_SIZE:
                    raise Exception(
                        f"Buffer has {len(buf)} bytes which is larger than "
                        + f"the maximum transmission unit / physical paket size {MAX_SIZE}"
                    )
                await loop.run_in_executor(None, tun.write, buf)
            try:
                os.unlink(os.path.join(dirpath, file))
            except OSError as e:
                logging.warning("ERROR %s", e)

        await asyncio.sleep(0.1)  # Prevent busy looping


async def main() -> None:
    args = parse_args()

    netconfig = get_netconfig()
    signal.signal(
        signal.SIGINT, signal_handler(args.ifname, args.server, args.ip, netconfig)
    )

    tun = tun_setup(args.ifname, args.ip, args.server)

    try:
        await asyncio.gather(
            asyncio.create_task(from_tun(args.dirpath, args.ip, tun)),
            asyncio.create_task(from_fs(args.dirpath, args.ip, tun)),
        )
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
