#! python3
from bitstream import BitStream
from numpy import int8, uint8
from crcmod import predefined
from pprint import pprint
from os.path import getsize
from collections import deque
from itertools import count
from struct import pack
import socket

PFMT = ("\033[46m[%04d]\033[0m\033[36m(%02d)\033[0m %d|\033[36m%d\033[0m|%d "
        "%d <\033[92m%.3f%%\033[0m>")
RFMT = "\033[1m\033[91m%s\033[0m"
GFMT = "\033[1;32m%s\033[0m"
S = " " * 3
PACKET_SIZE = 184 * 8  # In bits
PES_WITH_EXTENSION = set([0xBD])
PES_WITH_EXTENSION.update(range(0xC0, 0xDF + 1))
PES_WITH_EXTENSION.update(range(0xE0, 0xEF + 1))
EIT_ACTUAL = set([0x4E])
EIT_ACTUAL.update(range(0x50, 0x5F + 1))
PES_MASK = 0b000000000000000000000001
MIP_MASK = 0b010001111110000000001111
TEI_MASK = 0b000000001000000000000000
crc32 = predefined.mkCrcFun("crc-32-mpeg")


class CException(Exception):
    pass


def mjd2date(mjd):
    # TODO: Fix it
    yearDelay = mjd - 15078.2
    year = int(yearDelay / 365.25)
    monthDelay = mjd - 14956.1 - int(yearDelay)
    month = int(monthDelay / 30.6001)
    day = int(mjd - 14956 - int(yearDelay) - int(monthDelay))
    k = (month == 14 or month == 15)
    year += k
    month -= 1 + k * 12
    return (year, month, day)


def bcd2hour(bcd):
    s = hex(bcd)[2:].rjust(6, "0")
    return [int(i) for i in (s[:2], s[2:4], s[4:])]


def read_uint(stream, n):
    return sum(i << a for a, i in enumerate(stream.read(bool, n)[::-1]))


def toBits(b):
    return ((b & 0x80) >> 7, (b & 0x40) >> 6, (b & 0x20) >> 5, (b & 0x10) >> 4,
            (b & 0x08) >> 3, (b & 0x04) >> 2, (b & 0x02) >> 1, b & 0x01)


def read_descriptor(stream):
    tag = stream.read(uint8)
    length = stream.read(uint8)
    data = stream.read(bytes, length)
    return tag, data


def read_descriptors(stream):
    out = []
    while stream:
        out.append(read_descriptor(stream))
    return out


def read_timestamp(stream):
    ts = read_uint(stream, 3) << 30
    stream.read(bool, 1)
    ts += read_uint(stream, 15) << 15
    stream.read(bool, 1)
    ts += read_uint(stream, 15)
    stream.read(bool, 1)
    return ts


def read_based_timestamp(stream):
    stream.read(bool, 2)
    base = read_timestamp(stream)
    extension = read_uint(stream, 9)
    stream.read(bool, 1)
    return base * 300 + extension


def check(stream):
    length = len(stream)
    stuffing = stream.read(bool, length)
    if all(stuffing):
        return "**%d Stuffing Bytes" % (length // 8)
    else:
        raise Exception("Bits left in stream:\n%s" %
                        "".join("01"[i] for i in stuffing))


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
        self.skipNotPusi = kw.pop("skipNotPusi", False)
        self.skipPes = kw.pop("skipPes", False)
        self.skipPsi = kw.pop("skipPsi", False)
        self.ignoreAdaptation = kw.pop("ignoreAdaptation", False)
        self.ignorePayload = kw.pop("ignorePayload", False)
        self.hideLeft = kw.pop("hideLeft", False)
        self.kw = kw
        self.log = deque()

    def inf(self, s):
        self.log.append(s)

    def parse(self):
        """Enter a loop that parses the stream and prints the info"""
        # Prepare the file / udp
        kw = self.kw
        if "path" in kw:
            read = read_file(kw["file"])
            fSize = getsize(kw["file"]) // 188
        elif "ip" in kw and "port" in kw:
            read = read_udp(kw["ip"], kw["port"])
            fSize = float("inf")
        else:
            print(RFMT % "Not enough paramaters given")
            print("Give either a file path or an ip and a port")
            return
        # Start the variables
        self.pat = {}
        self.pes = {}
        self.pmt = {}
        self.cShow = False
        # Load the local ones
        log = self.log
        log_clear = log.clear
        pat = self.pat
        skipPids = self.skipPids
        skipNotPusi = self.skipNotPusi
        ignoreAdaptation = self.ignoreAdaptation
        ignorePayload = self.ignorePayload
        lastCounter = {}
        for i in count(0, 100):
            # Read the least information possible in case of skiping
            sync = read(1)[0]
            if sync != 0x47:
                raise CException("Sync should be 0x47, it is 0x%x" % sync)
            flagsAndPid = read(2)
            pid = ((flagsAndPid[0] & 0x1F) << 8) + flagsAndPid[1]
            if pid in skipPids:
                read(185)
                continue
            pusi = (flagsAndPid[0] & 0x40) >> 6
            if skipNotPusi:
                read(185)
                continue
            # Show log of previous packet
            if self.cShow and log:
                print("\n".join(log))
            log_clear()
            self.cShow = True
            # Read the rest of the flags and print
            tei = (flagsAndPid[0] & 0x80) >> 7
            priority = (flagsAndPid[0] & 0x20) >> 5
            extraFlags = read(1)[0]
            tsc = (extraFlags & 0xC0) >> 6
            counter = extraFlags & 0x0F
            print(PFMT % (pid, counter, tei, pusi, priority, tsc, i / fSize))
            # Check for errors in the packet
            if tei:
                self.inf(RFMT % "\033[7Transport Error Indicator (TEI)\033[0")
            last = lastCounter.pop(pid, -1)
            if (last + 1) % 16 != counter:
                if last == -1:
                    self.inf(GFMT % "First time we receive this PID")
                else:
                    self.inf(RFMT % ("Counter discontinuity, from %d to %d" %
                             (last, counter)))
            lastCounter[pid] = counter
            left = 184
            # Parse adaptation
            if extraFlags & 0x20:
                length = read(1)[0]
                if length:
                    adaptation = read(length)
                    if not ignoreAdaptation:
                        self.parse_adaptation(adaptation)
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
                    self.parse_payload(payload)
                    if self.cIncomplete:
                        self.inf(S + RFMT % "Incomplete payload")

    def parse_adaptation(self, data):
        """Parse very few parameters of adaptation
            There are 8 bit flags in the following order:
                [0] discontinuity, [1] rai, [2] streamPriority, [3] pcr,
                [4] opcr, [5] splice, [6] private, [7] extension"""
        flags = toBits(data[0])
        self.inf("   ADAPTATION(%03d) %d|%d|%d|%d|%d|%d|%d|%d" %
                 (len(data), *flags))
        if flags[3]:
            pcr = parse_based_timestamp_2(data[1:7])
            self.inf("   PCR -> %d" % pcr)
            if flags[4]:
                opcr = parse_based_timestamp_2(data[7:13])
                self.inf("   OPCR -> %d" % opcr)
        # Rest of the data is ignored

    def parse_payload(self, data):
        self.inf("   PAYLOAD(%03d)" % (len(data)))
        if data[0] | data[1] == 0 and data[2] == 1:
            if self.skipPes:
                self.cShow = False
                return
            self.parse_PES(data)
        elif data[0] == 0x47 and data[1] | 0x80 == 0xE0 and data[2] == 0x0F:
            print("\n" * 5 + RFMT % ("DVB-MIP is not implemented") + "\n" * 5)
        else:
            if self.skipPsi:
                self.cShow = False
                return
            self.parse_PSI(data)

    def parse_PES(self, data, n=0):
        data.read(bytes, 3)
        streamId = data.read(uint8)
        pesLength = read_uint(data, 16)
        hasExtension = streamId in PES_WITH_EXTENSION
        self.inf(S * n + "PES[%03d](%d)>%d" %
                 (streamId, pesLength, hasExtension))
        if hasExtension:
            data.read(bool, 2)
            scrambling = read_uint(data, 2)
            (priority, alignment, copyrighted, original, ptsF, dtsF, escrF,
             esRateF, dsmTrickF, copyF, crcF, extensionF) = data.read(bool, 12)
            length = data.read(uint8)
            args = (length, priority, alignment, copyrighted, original, ptsF,
                    dtsF, escrF, esRateF, dsmTrickF, copyF, crcF, extensionF)
            self.inf(S * n + "HEADER(%d) %d|%d|%d|%d "
                     "%d|%d|%d|%d|%d|%d|%d|%d" % args)
            header = data.read(BitStream, length * 8)
            if ptsF:
                header.read(bool, 4)
                pts = read_timestamp(header)
                self.inf(S * n + "PTS -> %d" % pts)
                if dtsF:
                    header.read(bool, 4)
                    dts = read_timestamp(header)
                    self.inf(S * n + "DTS -> %d" % dts)
            if escrF:
                header.read(bool, 2)
                escr = read_based_timestamp(header)
                self.inf(S * n + "ESCR -> %d" % escr)
            if esRateF:
                header.read(bool)
                rate = read_uint(header, 22)
                header.read(bool)
            if dsmTrickF:
                dsmTrick = header.read(uint8)
            if copyF:
                header.read(bool)
                copy = read_uint(header, 7)
            if crcF:
                crc = read_uint(header, 16)
            if extensionF:
                (privateF, fieldF, counterF,
                 pstdF, _, _, _, extension2F) = header.read(bool, 8)
                if privateF:
                    private = header.read(bytes, 16)
                if fieldF:
                    field = header.read(uint8)
                if counterF:
                    header.read(bool)
                    counter = read_uint(header, 7)
                    header.read(bytes)
                if pstdF:
                    scale = [128, 1024][header.read(bool)]
                    bufferSize = read_uint(header, 13) * scale
                if extension2F:
                    header.read(bool)
                    fieldLength = read_uint(header, 7)
                    header.read(bytes, fieldLength)
            if header:
                self.inf(S * n + check(header))
        if data and not self.ignoreLeft:
            self.inf(S * n + str(data.read(bytes, len(data) // 8)))

    def parse_PSI(self, data, n=0):
        data.read(bytes, data.read(uint8))
        copy = data.copy(24)
        tableId = data.read(uint8)
        syntaxF, privateBitF = data.read(bool, 2)
        data.read(bool, 2)
        length = read_uint(data, 12)
        self.inf(S * n + "PSI[%03d](%d) %d|%d" %
                 (tableId, length, syntaxF, privateBitF))
        if length > len(data) // 8:
            length = len(data) // 8
            self.cIncomplete = True
        if syntaxF and length:
            syntax = data.read(BitStream, length * 8)
            copy.write(syntax.copy(length * 8 - 32))
            tableIdExtension = read_uint(syntax, 16)
            syntax.read(bool, 2)
            version = read_uint(syntax, 5)
            currentF = syntax.read(bool)
            section, last = syntax.read(uint8, 2)
            tableData = syntax.read(BitStream, len(syntax) - 32)
            self.inf(S * n + "Syntax[%03d](%d) v%d |%d| %d/%d" %
                     (tableIdExtension, len(tableData) // 8, version,
                      currentF, section, last))
            originalCrc = read_uint(syntax, 32)
            myCrc = crc32(copy.read(bytes, len(copy) // 8))
            if originalCrc != myCrc:
                text = ("CRC does not match (0x%x vs 0x%x)" %
                        (originalCrc, myCrc))
                self.inf(S * n + RFMT % text)
            if not (self.cPid or tableId or privateBitF):  # PAT
                while tableData:
                    programNum = read_uint(tableData, 16)
                    tableData.read(bool, 3)
                    programPid = read_uint(tableData, 13)
                    self.inf(S * n + "PAT %d - %d" % (programNum, programPid))
                    if currentF:
                        self.pat[programPid] = programNum
            elif self.cProgram >= 0 and not privateBitF:  # PMT
                if self.ignorePMT:
                    self.cShow = False
                    return
                tableData.read(bool, 3)
                pcrPid = read_uint(tableData, 13)
                tableData.read(bool, 4)
                length = read_uint(tableData, 12)
                if length:
                    programDescriptors = tableData.read(BitStream, length * 8)
                    self.inf(S * n + str(read_descriptors(programDescriptors)))
                while tableData:
                    streamType = tableData.read(uint8)
                    tableData.read(bool, 3)
                    elementatyPid = read_uint(tableData, 13)
                    tableData.read(bool, 4)
                    _length = read_uint(tableData, 12)
                    self.inf(S * (n + 1) + "PMT[%d][%d](%d)(%d) PCR -> %d" %
                             (elementatyPid, streamType, length,
                              _length, pcrPid))
                    if currentF:
                        self.pmt[elementatyPid] = pcrPid
                    if _length:
                        streamDescriptors = tableData.read(BitStream,
                                                           _length * 8)
                        self.inf(S * (n + 1) +
                                 str(read_descriptors(streamDescriptors)))
            elif self.cPid == 17 and tableId == 66:  # SDT
                networkId = read_uint(tableData, 16)
                tableData.read(bytes, 1)
                self.inf(S * (n + 1) + "SDT[%d]" % networkId)
                # TODO: PARSE IT
            elif self.cPid == 18:  # EIT
                if tableId not in EIT_ACTUAL:
                    self.inf(S * (n + 1) + "EIT from another TS, discarded")
                    return
                tsId = read_uint(tableData, 16)
                networkId = read_uint(tableData, 16)
                segment = tableData.read(uint8)
                lastTableId = tableData.read(uint8)
                self.inf(S * (n + 1) + "EIT[%d][%d] %d/ %d" %
                         (tsId, networkId, segment, lastTableId))
                while tableData:
                    eventId = read_uint(tableData, 16)
                    mjd = mjd2date(read_uint(tableData, 16))
                    bcd = bcd2hour(read_uint(tableData, 24))
                    duration = bcd2hour(read_uint(tableData, 24))
                    status = read_uint(tableData, 3)
                    freeCA = tableData.read(bool)
                    length = read_uint(tableData, 12)
                    timeStr = ("%d/%d/%d - %d:%d:%d for %d:%d:%d" %
                               (*mjd, *bcd, *duration))
                    self.inf(S * (n + 1) + "EVENT[%d](%d) %s %d|%d" %
                             (eventId, length, timeStr, status, freeCA))
                    if length > len(tableData) // 8:
                        break  # TODO: else complete
                    elif length:
                        descriptors = tableData.read(BitStream, length * 8)
                        self.inf(S * (n + 1) +
                                 str(read_descriptors(descriptors)))
            else:
                self.inf(S * n + RFMT % "Not registered")
            if tableData and not self.ignoreLeft:
                self.inf(S * n +
                         str(tableData.read(bytes, len(tableData) // 8)))
        if data:
            self.inf(S * n + check(data))


def main(**kw):
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    stream = Stream(skipPids, **kw)
    try:
        stream.parse()
    except (Exception) as e:
        print(RFMT % str(e))
        print("Happened while parsing:")
        print("\n".join(stream.log))
        pprint(stream.pat)
        pprint(stream.pes)
    else:
        print(RFMT % "END OF FILE")
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
    main(path=path, ignorePayload=True)
