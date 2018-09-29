#! python3
import iotools
import tstools
from subprocess import Popen
from multiprocessing import Process

"""
Process 0:
    1. Filter PAT (0x00) -> Launch 2
    2. Filter specific PMT (defined in PAT) -> Launch 3, Subprocess(1.1)
    3. Filter any PSI and edit if PAT, PMT, SDT, EIT --> Send to localhost:9876
    3*  Change Sync byte from 0x47 to 0x48
Process 1:
    1. FFMPEG --> Send to localhost:9876
Process 2:
    1. Listen to localhost:9876
    1*  Filter PES if sync byte == 0x47
    1*  Pass any if sync byte == 0x48

* By now ignore stuffing
"""

RFMT = "\033[1m\033[91m%s\033[0m"


def main(**kw):
    p = Process(target=listen, kwargs=kw)
    p.start()
    filter(**kw)


def filter(**kw):
    """Process 0"""
    program = kw.pop("program")
    # 1
    for payload in tstools.store_PSI(targetPids=(0,), **kw):
        pat = tstools.parse_PAT(payload)
        break
    reversedPat = dict((j, i) for i, j in pat.items())
    pmtPid = reversedPat[program]
    # 2
    for payload in tstools.store_PSI(targetPids=(pmtPid,), **kw):
        pmt = tstools.parse_PMT(payload)
        break
    p = ffmpeg(pmt, kw["path"])
    # 3
    for pid, pusi, pF, aF, packet in tstools.parsed_loop(targetPids=pmt, **kw):
        pass


def ffmpeg(pmt, inp):
    """Process 1"""
    maps = " ".join("-map i:%s" % hex(i) for i in pmt)
    streams = " ".join("-streamid %d:%d" % (a, i) for a, i in enumerate(pmt))
    line = ("ffmpeg -y -i %s %s %s -copy_unknown -c copy"
            " save.ts") % (inp, maps, streams)  # TODO udp://localhost:9876
    return Popen(line, shell=True)


def listen(**kw):
    """Process 2"""
    pass


if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    main(path=path, program=498)
