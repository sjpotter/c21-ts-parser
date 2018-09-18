#! python3
import iotools
import tstools

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
    if "targetPids" in kw:
        skipPids = set(range(1 << 13)) - set(kw.pop("targetPids"))
    else:
        skipPids = set(kw.pop("skipPids", tuple()))
    skipPids.add(8191)  # Stuffing packet


if __name__ == "__main__":
    path = ("/home/huxley/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    path = ("C:/users/angel/Desktop/20180727-145000"
            "-20180727-145500-RGE1_CAT2_REC.ts")
    main(path=path)
