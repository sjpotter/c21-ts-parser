#! python3
from bitstream import BitStream
from numpy import int8, uint8
from crcmod import predefined
from pprint import pprint
from collections import deque

TSC_OPTION = ["Not scrambled", "Reserved for future use",
              "Scrambled with even key", "Scrambled with odd key"]
PFMT = ("\033[0;44m[%04d]\033[42m(%02d)\033[0m %d|%d|%d %d|%d "
        "<\033[1;92m%.3f%%\033[0m> %s")
RFMT = "\033[1;31m%s\033[0m"
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


class Stream():
    def __init__(self, raw, ignorePids, **kw):
        self.raw = raw
        self.ignorePids = ignorePids
        self.onlyPusi = kw.pop("onlyPusi", False)
        self.ignorePES = kw.pop("ignorePES", False)
        self.hideAdaptation = kw.pop("hideAdaptation", False)
        self.ignorePMT = kw.pop("ignorePMT", False)
        self.ignorePSI = kw.pop("ignorePSI")
        self.ignorePAT = kw.pop("ignorePAT", False)
        self.ignoreLeft = kw.pop("ignoreLeft", False)
        self.log = deque()

    def inf(self, s):
        self.log.append(s)

    def parse(self):
        self.pat = {}
        self.pes = {}
        self.pcr = {}
        self.cShow = False
        pat = self.pat
        data = BitStream(self.raw)
        ignorePids = self.ignorePids
        onlyPusi = self.onlyPusi
        total = len(data)
        lastCounter = {}
        while data:
            if self.cShow:
                try:
                    print("\n".join(self.log))
                except TypeError:
                    print("\n".join(map(str, self.log)))
            self.log.clear()
            sync = data.read(uint8)
            if sync != 0x47:
                raise Exception("Sync should be 0x47, it is 0x%x" % sync)
            tei, pusi, priority = data.read(bool, 3)
            pid = read_uint(data, 13)
            if pid in ignorePids:
                data.read(bytes, 185)
                self.cShow = False
                continue
            tsc = TSC_OPTION[read_uint(data, 2)]
            adaptationF, payloadF = data.read(bool, 2)
            counter = read_uint(data, 4)
            left = data.read(BitStream, PACKET_SIZE)
            last = lastCounter.pop(pid, -1)
            if (last + 1) % 16 != counter:
                if last == -1:
                    self.inf(GFMT % "First time we receive this PID")
                else:
                    self.inf(RFMT % ("Counter discontinuity, from %d to %d" %
                             (last, counter)))
            lastCounter[pid] = counter
            if onlyPusi and not pusi:
                self.cShow = False
                continue
            self.inf(PFMT % (pid, counter, tei, pusi, priority, adaptationF,
                     payloadF, 100 - len(data) * 100 / total, tsc))
            if tei:
                self.inf(RFMT % "Transport Error Indicator (TEI)")
            self.cPid = pid
            self.cPusi = pusi
            self.cShow = True
            self.cIncomplete = False
            try:
                self.cProgram = pat[pid]
            except KeyError:
                self.cProgram = -1
            if adaptationF:
                length = left.read(uint8)
                if length:
                    if self.hideAdaptation:
                        left.read(bytes, length)
                    else:
                        self.parse_adaptation(left.read(BitStream,
                                                        length * 8), 1)
            if payloadF:
                if left:
                    self.parse_payload(left, 1)
            if self.cIncomplete:
                self.inf(S + RFMT % "Incomplete payload")

    def parse_adaptation(self, data, n=0):
        (discontinuity, rai, streamPriority, pcrF, opcrF, spliceF,
         privateF, extensionF) = data.read(bool, 8)
        self.inf(S * n + "ADAPTATION (%d)" % (len(data) // 8 + 1))
        self.inf(S * n + "FLAGS: %d|%d|%d|%d|%d|%d|%d|%d" %
                 (discontinuity, rai, streamPriority, pcrF, opcrF, spliceF,
                  privateF, extensionF))
        pcr = opcr = 0
        if pcrF:
            pcr = read_based_timestamp(data)
            self.inf(S + "PCR -> %d" % pcr)
            if opcrF:
                opcr = read_based_timestamp(data)
                self.inf(S * n + "OPCR -> %d" % opcr)
        if spliceF:
            splice = data.read(int8)
        if privateF:
            length = data.read(uint8)
            private = data.read(bytes, length)
        if extensionF:
            length = data.read(uint8)
            extension = data.read(BitStream, length * 8)
            ltwF, pieceWiseF, seamlessF = extension.read(bool, 3)
            self.inf(S * n + "EXTENSION (%d) %d|%d|%d" %
                     (length, ltwF, pieceWiseF, seamlessF))
            extension.read(bool, 5)
            if ltwF:
                valid = extension.read(bool, 1)
                offset = extension.read(BitStream, 15)
            if pieceWiseF:
                extension.read(bool, 2)
                rate = read_uint(extension, 22)
            if seamlessF:
                spliceType = read_uint(extension, 4)
                nextDts = read_timestamp(extension)
            if extension:
                raise Exception("Bits left in extension:\n%s" % extension)
        if data:
            self.inf(S * n + check(data))

    def parse_payload(self, data, n=0):
        self.inf(S * n + "PAYLOAD (%03d)" % (len(data) // 8))
        if self.cPusi:
            first = read_uint(data.copy(24), 24)
            if first == PES_MASK:
                if self.ignorePES:
                    self.cShow = False
                    return
                self.parse_PES(data, n + 1)
            elif first | TEI_MASK == MIP_MASK:
                raise NotImplementedError("DVB-MIP")
            else:
                if self.ignorePSI:
                    self.cShow = False
                    return
                self.parse_PSI(data, n + 1)

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
                if self.ignorePAT:
                    self.cShow = False
                    return
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
                        self.pcr[elementatyPid] = pcrPid
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


def main(path, **kw):
    with open(path, "rb") as f:
        raw = f.read()
    if "targetPids" in kw:
        ignorePids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        ignorePids = set(kw.pop("ignorePids", tuple()))
    stream = Stream(raw, ignorePids, **kw)
    try:
        stream.parse()
    except KeyboardInterrupt:
        print(RFMT % "Keyboard interrupt")
    except Exception as e:
        print(RFMT % str(e))
    pprint(stream.pat)
    pprint(stream.pes)
    print("\n".join(stream.log))
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
    main(path, onlyPusi=True, ignorePES=False, ignorePSI=True,
         hideAdaptation=True, ignorePMT=True, ignorePAT=True,
         ignoreLeft=False, ignorePids=(21,))
