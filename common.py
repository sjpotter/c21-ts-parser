#! python3
import iotools

PFMT = "\033[46m[%04d]\033[0m<\033[92m%.3f%%\033[0m>"
RFMT = "\033[1m\033[91m%s\033[0m"


def loop(**kw):
    """Loop the stream and yield packets"""
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    # Prepare the file / udp
    if "path" in kw:
        read = iotools.read_file(kw["path"])
    elif "ip" in kw and "port" in kw:
        read = iotools.read_udp(kw["ip"], kw["port"])
    else:
        print(RFMT % "Not enough paramaters given")
        print("Give either a file path or an ip and a port")
        return
    # Start loop
    while True:
        try:
            sync = read(1)[0]
        except IndexError:
            break
        if sync != 0x47:
            raise Exception("Sync should be 0x47, it is 0x%x" % sync)
        flagsAndPid = read(2)
        pid = ((flagsAndPid[0] & 0x1F) << 8) + flagsAndPid[1]
        if pid in skipPids:
            read(185)
            continue
        yield b"\x47" + flagsAndPid + read(185)

def parsed_loop(**kw):
    """Extract and list basic information from the packets"""
    for packet in loop(**kw):
        pid = ((packet[1] & 0x1F) << 8) + packet[2]
        tei = (packet[1] & 0x80) >> 7
        pusi = (packet[1] & 0x40) >> 6
        priority = (packet[1] & 0x20) >> 5
        tsc = (packet[3] & 0xC0) >> 6
        counter = packet[3] & 0x0F
        yield (pid, tei, pusi, priority, tsc, counter, packet[4:])
