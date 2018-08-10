#! python3
import socket
from struct import pack
from threading import Thread
from collections import deque


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


def write_file(path):
    """Write to a ts file at path"""
    def wrapper(data):
        with open(path, "ab") as f:
            f.write(data)
    return (wrapper, "simple")


def write_file_queue(path):
    """Write to a ts file at path locking it until it finishes"""
    def wrapper(queue):
        f = open(path, "ab")
        f_write = f.write
        queue_popleft = queue.popleft
        for i in queue.copy():
            f_write(i)
            queue_popleft()
        f.close()
    return (wrapper, "complex")


def write_udp(ip, port):
    """Write to udp://ip:port"""
    def wrapper(data):
        s_sendto(data, pair)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    pair = (ip, port)
    s_sendto = s.sendto
    return (wrapper, "simple")


class Writer():
    def __init__(self, write):
        self.on = True
        self.queue = deque()
        self.thread = Thread(target=self.loop, daemon=True)
        self.writeArgs = write
        self.thread.start()

    def loop(self):
        queue = self.queue
        queue_copy = queue.copy
        queue_popleft = queue.popleft
        write, name = self.writeArgs
        if name == "simple":
            while self.on:
                for i in queue_copy():
                    f_write(i)
                    queue_popleft()
        elif name == "complex":
            while self.on:
                write(queue)
        print("Exited the loop")
        if name == "simple":
            for i in queue_copy():
                f_write(i)
                queue_popleft()
        elif name == "complex":
            write(queue)

    def stop(self):
        self.on = False
        self.thread.join()
        print("Finished writing")
