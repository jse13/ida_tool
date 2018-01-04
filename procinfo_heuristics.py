from idaapi import *
from idc import *
import logging
logging.basicConfig(level=logging.DEBUG)

# Identifies and highlights access to the PEB
def procinfo_heuristic(f_asm, f_addrs):

    ret = False

    for idx, line in enumerate(f_asm):
        op = line.split(" ", 2)

        if op[0] == "mov" and "fs:30h" in op[2]:
            ret = True
            logging.debug("procinfo_heuristic: found PEB access at " + str(hex(f_addrs[idx])))
            SetColor(f_addrs[idx], CIC_ITEM, 0x00a5ff)
        
    return ret

    