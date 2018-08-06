#! python3
import socket
from struct import pack
from os.path import getsize
from itertools import count

PFMT = "\033[46m[%04d]\033[0m<\033[92m%.3f%%\033[0m>"
RFMT = "\033[1m\033[91m%s\033[0m"


def read_file(path):
    """Read from a ts file at path"""
    def wrapper(n):
        return f_read(n)
    f = open(path, "rb")
    f_read = f.read
    return wrapper


def read_udp(ip, port):
    """Read from udp://ip:port"""
    def wrapper(n):
        return s_recv(n)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    request = pack("4sl", socket.inet_aton(ip), socket.INADDR_ANY)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
    s_recv = s.recv
    return wrapper


def parse(**kw):
    """Enter a loop that parses the stream and prints the info"""
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    # Prepare the file / udp
    if "path" in kw:
        read = read_file(kw["path"])
        fSize = getsize(kw["path"]) // 188
    elif "ip" in kw and "port" in kw:
        read = read_udp(kw["ip"], kw["port"])
        fSize = float("inf")
    else:
        print(RFMT % "Not enough paramaters given")
        print("Give either a file path or an ip and a port")
        return
    # Start loop
    out = kw.pop("out", "save.ts")
    show = kw.pop("show", False)
    for i in count(0, 100):
        sync = read(1)[0]
        if sync != 0x47:
            raise Exception("Sync should be 0x47, it is 0x%x" % sync)
        flagsAndPid = read(2)
        pid = ((flagsAndPid[0] & 0x1F) << 8) + flagsAndPid[1]
        if pid in skipPids:
            read(185)
            continue
        if show:
            print(PFMT % (pid, i / fSize))
        with open(out, "ab") as f:
            f.write(b"\x47" + flagsAndPid + read(185))

if __name__ == "__main__":
    path = ("/home/path")
    parse(path=path, out="save.ts", show=True, skipPids=(0x192, 0x193, 0x194))
