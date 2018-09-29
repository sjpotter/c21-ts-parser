#! python3
import iotools
from time import gmtime

RFMT = "\033[1m\033[91m%s\033[0m"
MJD_TO_UNIX = 40588
DAY = 86400
crcPol = 0x04c11db7
crcTable = []
crcBigMask = 0xFFFFFFFF
crcSmallMask = 0x80000000
for i in range(256):
    rev = i << 24
    for j in range(8):
        if rev & crcSmallMask:
            rev = (rev << 1) ^ crcPol
        else:
            rev <<= 1
    crcTable.append(rev & crcBigMask)


def crc32(b):
    """Ts custom crc"""
    value = crcBigMask
    for i in b:
        value = ((value << 8) ^ crcTable[(value >> 24) ^ i]) & crcBigMask
    return value


def try_decode(b):
    """Try to decode without throwing any error"""
    try:
        return b.decode()
    except UnicodeDecodeError:
        return "".join(chr(i) for i in b)


def toBits(b):
    """Return an 8 items list containing each bit in a byte"""
    return ((b & 0x80) >> 7, (b & 0x40) >> 6, (b & 0x20) >> 5, (b & 0x10) >> 4,
            (b & 0x08) >> 3, (b & 0x04) >> 2, (b & 0x02) >> 1, b & 0x01)


def parse_mjd(b):
    toUnix = ((b[0] << 8) + b[1] - MJD_TO_UNIX + 1) * DAY
    toTime = gmtime(toUnix)
    return (toTime.tm_year, toTime.tm_mon, toTime.tm_mday)


def parse_bcd(b):
    return tuple(int(hex(b[i])[2:]) for i in range(3))


def parse_timestamp_2(b):
    """0123456701234567012345670123456701234567 (5 bytes)
       --***-***************-***************---"""
    return (((b[0] & 0x38) << 30) + ((b[0] & 0x03) << 28) +
            (b[1] << 20) +
            ((b[2] & 0xF8) << 15) + ((b[2] & 0x03) << 13) +
            (b[3] << 5) +
            ((b[4] & 0xF8) >> 3))


def parse_based_timestamp_2(b):
    """6 bytes. ~5 bytes of base and ~2 of extension"""
    base = parse_timestamp_2(b)
    extension = ((b[4] & 0x03) << 7) + ((b[5] & 0xFE) >> 1)
    return base * 300 + extension


def parse_pcr(b):
    base = (b[0] << 25) + (b[1] << 17) + (b[2] << 11) + (b[3] << 3) + b[4] >> 5
    extension = ((b[4] & 0x01) << 8) + b[5]
    return base * 300 + extension


def parse_crc(b):
    """Parse a 32 bit CRC"""
    return (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]


def parse_descriptors(data, length):
    """Return data cut from length and descriptors as pairs (tag, data)"""
    out = []
    while length:
        dTag = data[0]
        dLength = data[1]
        dData = data[2:dLength + 2]
        length -= dLength + 2
        data = data[dLength + 2:]
        out.append((dTag, dData))
    return data, out


def parse_PAT(data):
    pat = {}
    # Get headers
    length = ((data[1] & 0x0F) << 8) + data[2] + 3
    if length < len(data):
        data = data[:length]
    data = data[8:-4]
    # Associate program numbers to PIDs
    for i in range(0, len(data), 4):
        programNum = (data[i] << 8) + data[i + 1]
        programPid = ((data[i + 2] & 0x1F) << 8) + data[i + 3]
        pat[programPid] = programNum
    return pat


def parse_PMT(data):
    pmt = []
    # Get headers
    length = ((data[1] & 0x0F) << 8) + data[2] + 3
    if length < len(data):
        data = data[:length]
    data = data[8:-4]
    # Parse program descriptors
    programLength = ((data[2] & 0x03) << 8) + data[3]
    data, _ = parse_descriptors(data[4:], programLength)
    while data:
        # Get pid of the ES
        ePid = ((data[1] & 0x1F) << 8) + data[2]
        pmt.append(ePid)
        # Parse ES descriptors
        esLength = ((data[3] & 0x03) << 8) + data[4]
        data, _ = parse_descriptors(data[5:], esLength)
    return pmt


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
        Exception(RFMT % "Not enough parameters given\n"
                  "Give either a file path or an ip and a port")
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
        pusi = packet[1] & 0x40
        pF = packet[3] & 0x10
        aF = packet[3] & 0x20
        yield (pid, pusi, pF, aF, packet)


def store_PSI(**kw):
    """Store and yield PSI data"""
    packets = {}
    for pid, pusi, pF, aF, packet in parsed_loop(**kw):
        if not pF:
            continue
        offset = 4
        if aF:  # Skip adaptation field
            length = packet[4]
            offset += 1 + length
        data = packet[offset:]
        if pusi:
            if data[0] | data[1] == 0 and data[2] == 1:  # PES
                continue
            elif (data[0] == 0x47 and data[1] | 0x80 == 0xE0 and
                  data[2] == 0x0F):  # DVB-MIP
                continue
            else:  # PSI
                if pid in packets:
                    yield packets[pid]
                packets[pid] = data[data[0] + 1:]
        else:
            try:
                packets[pid] += data
            except KeyError:
                pass  # Incomplete data does not match previous PID


def filter_PES(**kw):
    """Like loop() but only yields PES packets"""
    for _, _, pF, aF, packet in parsed_loop(**kw):
        if not pF:
            continue
        offset = 4
        if aF:  # Skip adaptation field
            length = packet[4]
            offset += 1 + length
        if not (packet[offset] | packet[offset + 1] == 0 and
                packet[offset + 2] == 1):  # Not PES
            continue
        yield packet
