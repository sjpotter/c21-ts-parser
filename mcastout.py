import socket

MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
path = ("C:/users/angel/Desktop/20180727-145000"
        "-20180727-145500-RGE1_CAT2_REC.ts")
with open(path, "rb") as f:
    data = f.read()
last = 0
while True:
    for i in range(188, len(data), 188):
        sock.sendto(data[last:i], (MCAST_GRP, MCAST_PORT))
        last = i
    print("Looped once")