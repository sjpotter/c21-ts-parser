#! python3
from bitstream import BitStream
from numpy import int8, uint8
from zlib import crc32

TSC_OPTION = ["Not scrambled", "Reserved for future use",
              "Scrambled with even key", "Scrambled with odd key"]
PFMT = ("\033[0;44m[%04d]\033[42m(%02d)\033[0m %d|%d|%d %d|%d "
        "<\033[1;92m%.3f%%\033[0m> %s")
RFMT = "\033[1;31m%s\033[0m"
S3, S4, S5 = " " * 3, " " * 4, " " * 5
PACKET_SIZE = 184 * 8  # In bits

PES_MASK = 0b000000000000000000000001
MIP_MASK = 0b010001111110000000001111
TEI_MASK = 0b000000001000000000000000


def read_uint(stream, n):
    return sum(i << a for a, i in enumerate(stream.read(bool, n)[::-1]))


def tprint(n, s, width=3):
    print(" " * n * width + s)


class Stream():
    def __init__(self):
        self.pat = {}

    def parse_packet(self, data, pid, pusi, adaptationF, payloadF):
        self.cPid = pid
        self.cPusi = pusi
        self.cIncomplete = False
        if adaptationF:
            length = data.read(uint8)
            if length:
                self.parse_adaptation(data.read(BitStream, length * 8), 1)
        if payloadF:
            if data:
                self.parse_payload(data, 1)
        if self.cIncomplete:
            print(S3 + RFMT % "Incomplete payload")

    def parse_adaptation(self, data, n=0):
        (discontinuity, rai, streamPriority, pcrF, opcrF, spliceF,
         privateF, extensionF) = data.read(bool, 8)
        tprint(n, "ADAPTATION (%d)" % (len(data) // 8 + 1))
        tprint(n, "FLAGS: %d|%d|%d|%d|%d|%d|%d|%d" % (discontinuity, rai,
               streamPriority, pcrF, opcrF, spliceF, privateF, extensionF))
        for i in range(pcrF + opcrF):
            base = read_uint(data, 33)
            _ = data.read(bool, 6)
            extension = read_uint(data, 9)
            if pcrF and not i:
                pcr = base * 300 + extension
                tprint(n, "PCR -> %d" % pcr)
            else:
                opcr = base * 300 + extension
                tprint(n, "OPCR -> %d" % opcr)
        if spliceF:
            splice = data.read(int8)
            tprint(n, "Splice Countdown: %d" % splice)
        if privateF:
            length = data.read(uint8)
            private = data.read(bytes, length)
            tprint(n, "Private: %s" % private)
        if extensionF:
            length = data.read(uint8)
            extension = data.read(BitStream, length * 8)
            ltwF, pieceWiseF, seamlessF = extension.read(bool, 3)
            tprint(n + 1, "EXTENSION (%d)" % length)
            tprint(n + 1, "FLAGS: %d|%d|%d" % (ltwF, pieceWiseF, seamlessF))
            extension.read(bool, 5)
            if ltwF:
                valid = extension.read(bool, 1)
                offset = extension.read(BitStream, 15)
                tprint(n + 1, "LTW %svalid offset: %s" %
                       (["in", ""][valid], offset))
            if pieceWiseF:
                extension.read(bool, 2)
                rate = read_uint(extension, 22)
                tprint(n + 1, "Piecewise rate: %d" % rate)
            if seamlessF:
                spliceType = read_uint(extension, 4)
                nextDts = read_uint(extension, 36) & 0x0efffefffe
                tprint(n + 1, "Type: %d Next DTS: %d" % (spliceType, nextDts))
            if extension:
                raise Exception("Bits left in extension: %s" % extension)
        if data:
            length = len(data)
            stuffing = data.read(bool, length)
            if all(stuffing):
                tprint(n, "**%d Stuffing Bytes" % (length // 8))
            else:
                raise Exception("Bits left in adaptation: %s" %
                                "".join("01"[i] for i in stuffing))

    def parse_payload(self, data, n=0):
        tprint(n, "PAYLOAD (%03d)" % (len(data) // 8))
        if self.cPusi:
            first = read_uint(data.copy(24), 24)
            if first == PES_MASK:
                self.parse_PES(data, n + 1)
            elif first | TEI_MASK == MIP_MASK:
                raise NotImplementedError("DVB-MIP")
            else:
                self.parse_PSI(data, n + 1)

    def parse_PES(self, data, n=0):
        data.read(bytes, 3)
        streamId = data.read(uint8)
        length = read_uint(data, 16)
        tprint(n, "PES[%03d](%d)" % (streamId, length))
        if length > len(data) // 8:
            length = len(data) // 8
            self.cIncomplete = True

    def parse_PSI(self, data, n=0):
        data.read(bytes, data.read(uint8))
        copy = data.copy(24)
        tableId = data.read(uint8)
        syntaxF, privateBitF = data.read(bool, 2)
        data.read(bool, 2)
        length = read_uint(data, 12)
        tprint(n, "PSI[%03d](%d) %d|%d" %
               (tableId, length, syntaxF, privateBitF))
        if length > len(data) // 8:
            length = len(data) // 8
            self.cIncomplete = True
        if syntaxF and length:
            syntax = data.read(BitStream, length * 8)
            copy.write(syntax.copy(length - 32))
            tableIdExtension = read_uint(syntax, 16)
            syntax.read(bool, 2)
            version = read_uint(syntax, 5)
            currentF = syntax.read(bool)
            section, last = syntax.read(uint8, 2)
            tableData = syntax.read(BitStream, len(syntax) - 32)
            tprint(n, "Syntax[%03d](%d) v%d |%d| %d/%d" %
                   (tableIdExtension, len(tableData) // 8, version,
                    currentF, section, last))
            originalCrc = read_uint(syntax, 32)
            myCrc = crc32(copy.read(bytes, len(copy) // 8))
            if originalCrc != myCrc:
                text = ("CRC does not match (0x%x vs 0x%x)" %
                        (originalCrc, myCrc))
                tprint(n, RFMT % text)
            if not (self.cPid or tableId or privateBitF):
                while tableData:
                    programNum = read_uint(tableData, 16)
                    tableData.read(bool, 3)
                    programPid = read_uint(tableData, 13)
                    tprint(n + 1, "PAT %d - %d" % (programNum, programPid))
                    self.pat[programPid] = programNum
            elif self.cPid in self.pat and not privateBitF:
                tableData.read(bool, 3)
                pcrPid = read_uint(tableData, 13)
                tableData.read(bool, 4)
                length = read_uint(tableData, 12)
                programDescriptors = tableData.read(bytes, length)
                # TODO: Parse descriptors
                # https://en.wikipedia.org/wiki/Program-specific_information#Descriptor
                tprint(n + 1, str(programDescriptors))
                streamType = tableData.read(uint8)
                tableData.read(bool, 3)
                elementatyPid = read_uint(tableData, 13)
                tableData.read(bool, 4)
                _length = read_uint(tableData, 12)
                tprint(n + 1, "PMT[%d][%d](%d)(%d) PCR -> %d" %
                       (elementatyPid, streamType, length, _length, pcrPid))
                streamDescriptors = tableData.read(bytes, _length)
                # TODO: Parse descriptors
                tprint(n + 1, str(streamDescriptors))
            if tableData:
                tprint(n, str(tableData))
        if data:
            length = len(data)
            stuffing = data.read(bool, length)
            if all(stuffing):
                tprint(n, "**%d Stuffing Bytes" % (length // 8))
            else:
                raise Exception("Bits left in PSI: %s" %
                                "".join("01"[i] for i in stuffing))


def main(path, targetPids=None, ignorePids=tuple(), onlyPusi=False):
    stream = Stream()
    with open(path, "rb") as f:
        raw = f.read()
    data = BitStream(raw)
    total = len(data)
    lastCounter = {}
    if targetPids:
        ignorePids = set(range(1 << 13)) - set(targetPids)
    else:
        ignorePids = set(ignorePids)
    while data:
        sync = data.read(uint8)
        if sync != 0x47:
            raise Exception("Sync should be 0x47, it is 0x%x" % sync)
        tei, pusi, priority = data.read(bool, 3)
        pid = read_uint(data, 13)
        tsc = TSC_OPTION[read_uint(data, 2)]
        adaptationF, payloadF = data.read(bool, 2)
        counter = read_uint(data, 4)
        left = data.read(BitStream, PACKET_SIZE)
        if pid in ignorePids:
            continue
        try:
            if (lastCounter[pid] + 1) % 16 != counter:
                text = ("Counter discontinuity, from %d to %d" %
                        (lastCounter[pid], counter))
                print(RFMT % text)
        except:
            pass
        lastCounter[pid] = counter
        if onlyPusi and not pusi:
            continue
        print(PFMT % (pid, counter, tei, pusi, priority,
              adaptationF, payloadF, 100 - len(data) * 100 / total, tsc))
        if tei:
            print(RFMT % "Transport Error Indicator (TEI)")
        stream.parse_packet(left, pid, pusi, adaptationF, payloadF)
    print(RFMT % "END OF FILE")


if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    main(path, onlyPusi=True, targetPids=(0,))
