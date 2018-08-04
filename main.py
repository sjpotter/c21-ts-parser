#! python3
from bitstream import BitStream
from numpy import int8, uint8
from zlib import crc32

TSC_OPTION = ["Not scrambled", "Reserved for future use",
              "Scrambled with even key", "Scrambled with odd key"]
PRINT_PRESET = ("\033[0;44m[%04d]\033[42m(%02d)\033[0m %d|%d|%d %d|%d "
                "<\033[1;92m%.3f%%\033[0m> %s")
PES_START = "000000000000000000000001"


def read_uint(stream, n):
    i = 0
    for _ in range(n):
        i <<= 1
        if stream.read(bool):
            i += 1
    return i


def tprint(n, s, width=5):
    print(" " * n * width + s)


def rprint(s):
    print("\033[1;31m%s\033[0m" % s)


def trprint(n, s, width=5):
    print(" " * n * width + "\033[1;31m%s\033[0m" % s)


def main(raw, ignorePids=(9999,), onlyPusi=False):
    data = BitStream(raw)
    total = len(data)
    pat = {}
    while data:
        sync = data.read(uint8)
        if sync != 0x47:
            raise Exception("Sync should be 0x47, it is 0x%x" % sync)
        tei, pusi, priority = data.read(bool, 3)
        pid = read_uint(data, 13)
        tsc = TSC_OPTION[read_uint(data, 2)]
        adaptationF, payloadF = data.read(bool, 2)
        counter = read_uint(data, 4)
        left = 184  # Header is 4 bytes
        if onlyPusi and not pusi:
            data.read(bytes, left)
            continue
        if pid in ignorePids:
            data.read(bytes, left)
            continue
        print(PRINT_PRESET % (pid, counter, tei, pusi, priority,
              adaptationF, payloadF, 100 - len(data) * 100 / total, tsc))
        if tei:
            rprint("Transport Error Indicator (TEI)")

        if adaptationF:
            length = data.read(uint8)
            left -= 1
        if adaptationF and length:
            adaptation = data.read(BitStream, length * 8)
            left -= length

            (discontinuity, rai, streamPriority, pcrF, opcrF, spliceF,
             privateF, extensionF) = adaptation.read(bool, 8)
            tprint(1, "ADAPTATION (%d)" % length)
            tprint(1, "FLAGS: %d|%d|%d|%d|%d|%d|%d|%d" % (discontinuity,
                   rai, streamPriority, pcrF, opcrF, spliceF, privateF,
                   extensionF))
            for i in range(pcrF + opcrF):
                base = read_uint(adaptation, 33)
                _ = adaptation.read(bool, 6)
                extension = read_uint(adaptation, 9)
                if pcrF and not i:
                    pcr = base * 300 + extension
                    tprint(1, "PCR -> %d" % pcr)
                else:
                    opcr = base * 300 + extension
                    tprint(1, "OPCR -> %d" % opcr)
            if spliceF:
                splice = adaptation.read(int8)
                tprint(1, "Splice Countdown: %d" % splice)
            if privateF:
                length = adaptation.read(uint8)
                private = adaptation.read(bytes, length)
                tprint(1, "Private: %s" % private)
            if extensionF:
                length = adaptation.read(uint8)
                extension = adaptation.read(BitStream, length * 8)
                ltwF, pieceWiseF, seamlessF = extension.read(bool, 3)
                tprint(2, "EXTENSION (%d)" % length)
                tprint(2, "FLAGS: %d|%d|%d" % (ltwF, pieceWiseF, seamlessF))
                extension.read(bool, 5)
                if ltwF:
                    valid = extension.read(bool, 1)
                    offset = extension.read(BitStream, 15)
                    tprint(2, "LTW %svalid offset: %s" %
                           (["in", ""][valid], offset))
                if pieceWiseF:
                    extension.read(bool, 2)
                    rate = read_uint(extension, 22)
                    tprint(2, "Piecewise rate: %d" % rate)
                if seamlessF:
                    spliceType = read_uint(extension, 4)
                    nextDts = read_uint(extension, 36) & 0x0efffefffe
                    tprint(2, "Type: %d Next DTS: %d" % (spliceType, nextDts))
                if extension:
                    raise Exception("Bits left in extension: %s" % extension)
            if adaptation:
                length = len(adaptation)
                stuffing = adaptation.read(bool, length)
                if all(stuffing):
                    tprint(1, "**%d Stuffing Bytes" % (length // 8))
                else:
                    raise Exception("Bits left in adaptation: %s" %
                                    "".join("01"[i] for i in stuffing))
        if payloadF:
            payload = data.read(BitStream, left * 8)
            tprint(1, "PAYLOAD (%03d)" % left)
            if pusi:
                if str(payload).startswith(PES_START):
                    payload.read(bytes, 3)
                    streamId = payload.read(uint8)
                    length = read_uint(payload, 16)
                    tprint(2, "PES[%03d](%d)" % (streamId, length))
                else:  # Assuming PSI
                    payload.read(bytes, payload.read(uint8))
                    copy = payload.copy(24)
                    tableId = payload.read(uint8)
                    syntaxF, privateBitF = payload.read(bool, 2)
                    payload.read(bool, 2)
                    length = read_uint(payload, 12)
                    tprint(2, "PSI[%03d](%d) %d|%d" %
                           (tableId, length, syntaxF, privateBitF))
                    if syntaxF and length:
                        syntax = payload.read(BitStream, length * 8)
                        copy.write(syntax.copy(len(syntax) - 32))
                        tableIdExtension = read_uint(syntax, 16)
                        syntax.read(bool, 2)
                        version = read_uint(syntax, 5)
                        currentF = syntax.read(bool)
                        section, last = syntax.read(uint8, 2)
                        tableData = syntax.read(BitStream, len(syntax) - 32)
                        originalCrc = read_uint(syntax, 32)
                        tprint(3, "Syntax[%03d](%d) v%d |%d| %d/%d" %
                               (tableIdExtension, len(tableData) // 8, version,
                                currentF, section, last))
                        myCrc = crc32(copy.read(bytes, len(copy) // 8))
                        if originalCrc != myCrc:
                            trprint(3, "CRC does not match (0x%x vs 0x%x)" %
                                    (originalCrc, myCrc))
                        if not (pid or tableId or privateBitF):
                            programNum = read_uint(tableData, 16)
                            tableData.read(bool, 3)
                            programPid = read_uint(tableData, 13)
                            tprint(4, "PAT %d - %d" % (programNum, programPid))
                            pat[programPid] = programNum
                        elif pid in pat and not privateBitF:
                            tableData.read(bool, 3)
                            pcrPid = read_uint(tableData, 13)
                            tableData.read(bool, 4)
                            length = read_uint(tableData, 12)
                            programDescriptors = tableData.read(bytes, length)
                            # TODO: Parse descriptors
                            # https://en.wikipedia.org/wiki/Program-specific_information#Descriptor
                            tprint(4, str(programDescriptors))
                            streamType = tableData.read(uint8)
                            tableData.read(bool, 3)
                            elementatyPid = read_uint(tableData, 13)
                            tableData.read(bool, 4)
                            _length = read_uint(tableData, 12)
                            tprint(4, "PMT[%d][%d](%d)(%d) PCR -> %d" %
                                   (elementatyPid, streamType, length, _length,
                                    pcrPid))
                            streamDescriptors = tableData.read(bytes, _length)
                            # TODO: Parse descriptors
                            tprint(4, str(streamDescriptors))
                        tprint(3, str(tableData))
                    if payload:
                        length = len(payload)
                        stuffing = payload.read(bool, length)
                        if all(stuffing):
                            tprint(2, "**%d Stuffing Bytes" % (length // 8))
                        else:
                            raise Exception("Bits left in payload: %s" %
                                            "".join("01"[i] for i in stuffing))
    print("END OF FILE")


if __name__ == "__main__":
    path = "20131211_102729-1920x1080p30.ts"
    with open(path, "rb") as f:
        data = f.read()
    main(data, onlyPusi=True, ignorePids=(2001, 2002))
