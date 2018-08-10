#! python3
from os.path import getsize
from itertools import count
import iotools

PFMT = "\033[46m[%04d]\033[0m<\033[92m%.3f%%\033[0m>"
RFMT = "\033[1m\033[91m%s\033[0m"


def parse(**kw):
    """Enter a loop that parses the stream and prints the info"""
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    # Prepare the file / udp
    if "path" in kw:
        read = iotools.read_file(kw["path"])
        fSize = getsize(kw["path"]) // 188
    elif "ip" in kw and "port" in kw:
        read = iotools.read_udp(kw["ip"], kw["port"])
        fSize = float("inf")
    else:
        print(RFMT % "Not enough paramaters given")
        print("Give either a file path or an ip and a port")
        return
    # Start loop
    out = kw.pop("out", "save.ts")
    every = kw.pop("every", 1)
    if fSize == float("inf"):
        every *= 2000000
    else:
        every *= fSize // 99.9 * 100
    writer = iotools.Writer(iotools.write_file_queue(out))
    write = writer.queue.append
    for i in count(0, 100):
        try:
            sync = read(1)[0]
        except IndexError:
            if i // 100 == fSize:
                break
        if sync != 0x47:
            raise Exception("Sync should be 0x47, it is 0x%x" % sync)
        flagsAndPid = read(2)
        pid = ((flagsAndPid[0] & 0x1F) << 8) + flagsAndPid[1]
        if pid in skipPids:
            read(185)
            continue
        if not i % every:
            print(PFMT % (pid, i / fSize))
        write(b"\x47" + flagsAndPid + read(185))
    print("Finished reading")
    writer.stop()

if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    path = ("C:/users/angel/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    parse(path=path, out="save.ts", skipPids=(0x192, 0x193, 0x194), every=10)
