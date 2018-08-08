#! python3
from pprint import pprint
from os.path import getsize
from collections import deque
from itertools import count
from struct import pack
from logging import exception
from time import gmtime
import socket

PFMT = ("\033[46m[%04d]\033[0m\033[36m(%02d)\033[0m %d|%d|%d "
        "%d <\033[92m%.3f%%\033[0m>")
RFMT = "\033[1m\033[91m%s\033[0m"
GFMT = "\033[1;32m%s\033[0m"
PES_WITH_EXTENSION = set([0xBD])
PES_WITH_EXTENSION.update(range(0xC0, 0xDF + 1))
PES_WITH_EXTENSION.update(range(0xE0, 0xEF + 1))
EIT_ACTUAL = set([0x4E])
EIT_ACTUAL.update(range(0x50, 0x5F + 1))
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
    value = crcBigMask
    for i in b:
        value = ((value << 8) ^ crcTable[((value >> 24) ^ i) & 0xFF]) & crcBigMask
    return value


class CException(Exception):
    """Custom Exception"""
    pass


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


class Stream():
    def __init__(self, skipPids, **kw):
        # Load the parameters
        self.skipPids = skipPids
        self.skipPes = kw.pop("skipPes", False)
        self.skipPsi = kw.pop("skipPsi", False)
        self.ignoreAdaptation = kw.pop("ignoreAdaptation", False)
        self.ignorePayload = kw.pop("ignorePayload", False)
        self.hideNotPusi = kw.pop("hideNotPusi", False)
        self.hidePat = kw.pop("hidePat", False)
        self.hidePmt = kw.pop("hidePmt", False)
        self.hideSdt = kw.pop("hideSdt", False)
        self.hideEit = kw.pop("hideEit", False)
        self.hideTdt = kw.pop("hideTdt", False)
        self.kw = kw
        self.log = deque()

    def inf(self, s):
        self.log.append(s)
    
    def ignore_pid(self, pid):
        self.skipPids.add(pid)
        self.packets.pop(pid, None)

    def parse(self):
        """Enter a loop that parses the stream and prints the info"""
        # Prepare the file / udp
        kw = self.kw
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
        # Start the variables
        self.td = (0, 0, 0, 0, 0, 0)
        self.pat = {}
        self.packets = {}
        self.pmt = {}
        self.pcr = {}
        self.sdt = {}
        self.eit = {}
        self.cShow = False
        # Load the local ones
        log = self.log
        log_clear = log.clear
        s_inf = self.inf
        s_parse_adaptation = self.parse_adaptation
        s_parse_payload = self.parse_payload
        pat = self.pat
        skipPids = self.skipPids
        ignoreAdaptation = self.ignoreAdaptation
        ignorePayload = self.ignorePayload
        hideNotPusi = self.hideNotPusi
        lastCounter = {}
        for i in count(0, 100):
            # Read the least information possible in case of skiping
            try:
                sync = read(1)[0]
            except IndexError:
                if i // 100 == fSize:
                    break
            if sync != 0x47:
                raise CException("Sync should be 0x47, it is 0x%x" % sync)
            flagsAndPid = read(2)
            pid = ((flagsAndPid[0] & 0x1F) << 8) + flagsAndPid[1]
            if pid in skipPids:
                read(185)
                continue
            # Show log of previous packet
            if self.cShow and log:
                print("\n".join(log))
            log_clear()
            self.cShow = True
            # Read the rest of the flags and print
            tei = (flagsAndPid[0] & 0x80) >> 7
            pusi = (flagsAndPid[0] & 0x40) >> 6
            priority = (flagsAndPid[0] & 0x20) >> 5
            extraFlags = read(1)[0]
            tsc = (extraFlags & 0xC0) >> 6
            counter = extraFlags & 0x0F
            s_inf(PFMT % (pid, counter, tei, pusi, priority, tsc, i / fSize))
            if hideNotPusi and not pusi:
                self.cShow = False
            # Check for errors in the packet
            if tei:
                s_inf(RFMT % "\033[7Transport Error Indicator (TEI)\033[0")
            last = lastCounter.pop(pid, -1)
            if last != counter:
                if last == -1:
                    s_inf(GFMT % "First time we receive this PID")
                else:
                    s_inf(RFMT % ("Counter discontinuity, from %d to %d" %
                          (last, counter)))
            lastCounter[pid] = (counter + 1 if extraFlags & 0x10 else 0) % 16
            left = 184
            # Parse adaptation
            if extraFlags & 0x20:
                length = read(1)[0]
                if length:
                    adaptation = read(length)
                    if not ignoreAdaptation:
                        s_parse_adaptation(adaptation)
                left -= length + 1
            # Parse payload
            if extraFlags & 0x10:
                payload = read(left)
                if not ignorePayload:
                    self.cPid = pid
                    self.cPusi = pusi
                    try:
                        self.cProgram = pat[pid]
                    except KeyError:
                        self.cProgram = -1
                    s_parse_payload(payload)

    def parse_adaptation(self, data):
        """Parse very few parameters of adaptation
            There are 8 bit flags in the following order:
                [0] discontinuity, [1] rai, [2] streamPriority, [3] pcr,
                [4] opcr, [5] splice, [6] private, [7] extension"""
        s_inf = self.inf
        flags = toBits(data[0])
        s_inf("   ADAPTATION (%03d) %d|%d|%d|%d|%d|%d|%d|%d" %
              (len(data), *flags))
        if flags[3]:
            pcr = parse_based_timestamp_2(data[1:7])
            s_inf("   PCR -> %d" % pcr)
            if flags[4]:
                opcr = parse_based_timestamp_2(data[7:13])
                s_inf("   OPCR -> %d" % opcr)
        # Rest of the data is ignored

    def parse_payload(self, data):
        cPid = self.cPid
        packets = self.packets
        if self.cPusi:
            if data[0] | data[1] == 0 and data[2] == 1:  # PES
                if self.skipPes:
                    self.ignore_pid(cPid)
                    self.cShow = False
                    return
                if cPid in packets:
                    print("It is", len(packets[cPid]))  # TODO: PARSE PES
                packets[cPid] = data[3:]
            elif (data[0] == 0x47 and data[1] | 0x80 == 0xE0 and
                  data[2] == 0x0F):  # DVB-MIP
                self.inf("\n\n\n\n\n" + RFMT % ("DVB-MIP is not implemented"))
                return
            else:  # PSI
                if self.skipPsi:
                    self.ignore_pid(cPid)
                    self.cShow = False
                    return
                if cPid in packets:
                    self.parse_PSI(packets[cPid])
                packets[cPid] = data[data[0] + 1:]
        else:
            try:
                packets[cPid] += data
            except KeyError:
                self.inf(RFMT % "Incomplete data does not match previous PID")

    def parse_PSI(self, data):
        s_inf = self.inf
        cPid = self.cPid
        # Get headers
        tableId = data[0]
        syntaxF = (data[1] & 0x80) >> 7
        privateF = (data[1] & 0x40) >> 6
        length = ((data[1] & 0x0F) << 8) + data[2] + 3
        if length < len(data):
            data = data[:length]
        s_inf("   PSI[%03d] (%d) %d|%d" % (tableId, length, syntaxF, privateF))
        # Checking TDT since it is a special shorter table
        if cPid == 20:  # TDT (and TOT)
            if tableId != 112:  # TDT
                self.cShow = False
                return
            if self.hideTdt:
                self.cShow = False
            data = data[-5:]
            date = parse_mjd(data)
            time = parse_bcd(data[2:])
            s_inf("   TDT: Actual time is %d:%d:%d %d/%d/%d" % (*date, *time))
            self.td = (*date, *time)
            return
        # Check CRC32
        originalCrc = parse_crc(data[-4:])
        data = data[:-4]
        myCrc = crc32(data)
        if originalCrc != myCrc:
            s_inf(RFMT % ("   CRC32 does not match: o{%d} m{%d}" %
                  (originalCrc, myCrc)))
        # Get extended headers
        if not (syntaxF and length):
            return
        tableIdExtension = (data[3] << 8) + data[4]
        version = data[5] & 0x3E
        currentF = data[5] & 0x01
        section = data[6]
        last = data[7]
        data = data[8:]
        if not currentF:
            s_inf(RFMT % "   PSI has no current flag: ignored")
        s_inf("   >[%03d] v%d %d/%d" %
              (tableIdExtension, version, section, last))
        # Clasify the table
        if not (cPid or tableId or privateF):  # PAT
            if self.hidePat:
                self.cShow = False
            # Associate program numbers to PIDs
            for i in range(0, len(data), 4):
                programNum = (data[i] << 8) + data[i + 1]
                programPid = ((data[i + 2] & 0x1F) << 8) + data[i + 3]
                s_inf("      PAT[%d] -> p%d" % (programPid, programNum))
                self.pat[programPid] = programNum
        elif tableId == 2 and not privateF:  # PMT
            if self.hidePmt:
                self.cShow = False
            if self.cProgram == -1:
                s_inf("      PMT: PID %d was nor registered in PAT")
                return
            # Get the PCR associated
            pcrPid = ((data[0] & 0x1F) << 8) + data[1]
            self.pcr[self.cProgram] = pcrPid
            # Parse program descriptors
            programLength = ((data[2] & 0x03) << 8) + data[3]
            data, programD = parse_descriptors(data[4:], programLength)
            for dTag, dData in programD:
                s_inf("      PMT TAG[%d]: %s" % (dTag, str(dData)))
            while data:
                # Get type and pid of the ES
                sType = data[0]
                ePid = ((data[1] & 0x1F) << 8) + data[2]
                self.pmt[self.cProgram] = (sType, ePid)
                s_inf("      PMT[%d]: (%d, %d)" % (self.cProgram, sType, ePid))
                # Parse ES descriptors
                esLength = ((data[3] & 0x03) << 8) + data[4]
                data, esD = parse_descriptors(data[5:], esLength)
                for dTag, dData in esD:
                    s_inf("      PMT TAG[%d]: %s" % (dTag, str(dData)))
        elif cPid == 17:  # SDT
            if self.hideSdt:
                self.cShow = False
            # Ignoring original_network_id (2 bytes)
            data = data[3:]
            while data:
                # Parse headers
                serviceId = (data[0] << 8) + data[1]
                running = (data[3] & 0xE0) >> 5
                s_inf("      SDT[%d] running: %d" % (serviceId, running))
                # Parse descriptors
                length = ((data[3] & 0x0F) << 8) + data[4]
                data, descriptors = parse_descriptors(data[5:], length)
                for dTag, dData in descriptors:
                    if dTag == 72:  # Service descriptor
                        serviceType = dData[0]
                        _length = dData[1]
                        serviceProvider = try_decode(dData[2:_length + 2])
                        serviceName = try_decode(dData[_length + 3:])
                        self.sdt[serviceId] = (serviceType, serviceProvider,
                                               serviceName)
                    elif dTag == 93:  # Multilingual
                        pass
                    else:
                        s_inf("      SDT TAG[%d]: %s" % (dTag, str(dData)))
        elif cPid == 18:  # EIT
            if self.hideEit:
                self.cShow = False
            if tableId not in EIT_ACTUAL:
                self.cShow = False
                return
            eventList = []
            # Ignoring tsId, OnId, lastN, lastId (6 bytes)
            data = data[6:]
            while data:
                # Parse headers
                eventId = (data[0] << 8) + data[1]
                date = parse_mjd(data[2:])
                hour = parse_bcd(data[4:])
                duration = parse_bcd(data[7:])
                running = (data[10] & 0xE0) >> 5
                s_inf("      EIT[%d] running: %d" % (eventId, running))
                s_inf("      .      %d-%d-%d %d:%d:%d (%d:%d:%d)" %
                      (*date, *hour, *duration))
                event = {"info": "", "extended": "", "date": date,
                         "hour": hour, "duration": duration, "streams": []}
                # Parse descriptors
                length = ((data[10] & 0x0F) << 8) + data[11]
                data, descriptors = parse_descriptors(data[12:], length)
                for dTag, dData in descriptors:
                    if dTag == 77:  # Info
                        lang = try_decode(dData[:3])
                        _length = dData[3]
                        eventName = try_decode(dData[4:_length + 4])
                        text = try_decode(dData[_length + 5:])
                        event["info"] = ";".join((lang, eventName, text))
                    elif dTag == 78:  # Extended
                        number = (dData[0] & 0xF0) >> 4
                        lang = try_decode(dData[1:4])
                        offset = dData[4] + 6
                        text = try_decode(dData[offset:])
                        if number == 0:
                            t = ";".join((lang, text))
                            event["extended"] = t + event["extended"]
                        else:
                            event["extended"] += text
                    elif dTag == 80:  # Component
                        content = dData[0] & 0x0F
                        lang = try_decode(dData[3:6])
                        event["streams"].append((lang, content))
                    else:
                        s_inf("      EIT TAG[%d]: %s" % (dTag, str(dData)))
                eventList.append(event)
            self.eit[tableIdExtension] = eventList
        elif tableId == 116:  # application information section
            self.ignore_pid(cPid)
            self.cShow = False
        else:
            s_inf("   UNRECOGNIZED %d, %d" % (cPid, tableId))


def main(**kw):
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    skipPids.add(8191)  # Stuffing packet
    skipPids.add(21)  # Network synchronization
    skipPids.add(1)  # CAT
    skipPids.add(16)  # NIT
    stream = Stream(skipPids, **kw)
    try:
        stream.parse()
    except KeyboardInterrupt:
        print(RFMT % "Keyboard Interrupt")
    except Exception as e:
        print(RFMT % str(e))
        exception(e)
        print("Happened while parsing:")
        print("\n".join(stream.log))
    else:
        print(RFMT % "END OF FILE")
    with open("output", "w") as f:
        print("PAT", file=f)
        pprint(stream.pat, stream=f)
        print("\n\nPMT", file=f)
        pprint(stream.pmt, stream=f)
        print("\n\nSDT", file=f)
        pprint(stream.sdt, stream=f)
        print("\n\nEIT", file=f)
        pprint(stream.eit, stream=f)
    print("Time and Date was %d/%d/%d %d:%d:%d" % stream.td)
    while True:
        try:
            input("\rPress enter to exit")
        except KeyboardInterrupt:
            pass
        else:
            break


if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    path = ("C:/users/angel/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    main(path=path, hideNotPusi=True, hidePmt=False, hidePat=True,
         hideSdt=True, hideEit=True, hideTdt=True, skipPes=True)
