#! python3
from crcmod import predefined
from pprint import pprint
from os.path import getsize
from collections import deque
from itertools import count
from struct import pack
from logging import exception
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
crc32 = predefined.mkCrcFun("crc-32-mpeg")


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
        self.kw = kw
        self.log = deque()

    def inf(self, s):
        self.log.append(s)

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
        self.pat = {}
        self.packets = {}
        self.pmt = {}
        self.pcr = {}
        self.sdt = {}
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
                if self.skipPes or 1:
                    self.skipPids.add(cPid)
                    self.cShow = False
                    return
                # TODO: Buffer and parse PES
            elif (data[0] == 0x47 and data[1] | 0x80 == 0xE0 and
                  data[2] == 0x0F):  # DVB-MIP
                self.inf("\n\n\n\n\n" + RFMT % ("DVB-MIP is not implemented"))
                return
            else:  # PSI
                if self.skipPsi:
                    self.skipPids.add(cPid)
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
        elif self.cProgram >= 0 and not privateF:  # PMT
            if self.hidePmt:
                self.cShow = False
            # Get the PCR associated
            pcrPid = ((data[0] & 0x1F) << 8) + data[1]
            self.pcr[self.cProgram] = pcrPid
            # Parse program descriptors
            programLength = ((data[2] & 0x03) << 8) + data[3]
            data, programD = parse_descriptors(data[4:], programLength)
            for dTag, dData in programD:
                s_inf("      PMT TAG[%d]: %s" % (dTag, str(dData)))
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
            if self.hideEit or tableId not in EIT_ACTUAL:
                self.cShow = False
            # Ignoring tsId, OnId, lastN, lastId (6 bytes)
            data = data[6:]
            while data:
                # Parse headers
                eventId = (data[0] << 8) + data[1]
                # TODO: Read starttime{mjd (2b), bcd (3b)} and duration(3b)
                startTime, duration = 0, 0
                running = (data[10] & 0xE0) >> 5
                s_inf("      EIT[%d] running: %d" % (eventId, running))
                # Parse descriptors
                length = ((data[10] & 0x0F) << 8) + data[11]
                data, descriptors = parse_descriptors(data[12:], length)
                for dTag, dData in descriptors:
                    s_inf("      EIT TAG[%d]: %s" % (dTag, str(dData)))
        elif tableId == 116:  # application information section
            self.skipPids.add(cPid)  # From now on skip this PID


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

    def parse__PSI(self, data, n=0):
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
    print("PAT")
    pprint(stream.pat)
    print("PMT")
    pprint(stream.pmt)
    print("SDT")
    pprint(stream.sdt)
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
    main(path=path, skipPes=True, hideNotPusi=True, hidePmt=True, hidePat=True,
         hideSdt=True)
