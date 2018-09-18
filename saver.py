#! python3
from os.path import getsize
from itertools import count
import iotools
import tstools

PFMT = "\033[46m[%04d]\033[0m<\033[92m%.3f%%\033[0m>"
RFMT = "\033[1m\033[91m%s\033[0m"


def parse(**kw):
    """Enter a loop that parses the stream and prints the info"""
    if "path" in kw:
        fSize = getsize(kw["path"]) // 188
    elif "ip" in kw and "port" in kw:
        fSize = float("inf")
    # Start loop
    out = kw.pop("out", "save.ts")
    every = kw.pop("every", 1)
    if fSize == float("inf"):
        every *= 2000000
    else:
        every *= fSize // 99.9 * 100
    writer = iotools.Writer(iotools.write_file_queue(out))
    write = writer.queue.append
    for i, packet in zip(count(0, 100), tstools.loop(**kw)):
        if not i % every:
            pid = ((packet[1] & 0x1F) << 8) + packet[2]
            print(PFMT % (pid, i / fSize))
        write(packet)
    print("Finished reading")
    writer.stop()

if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    path = ("C:/users/angel/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    parse(path=path, out="save.ts", skipPids=(0x192, 0x193, 0x194), every=10)
