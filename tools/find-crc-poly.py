import sys
import binascii
import struct
import crcmod
#from z3 import *

start = int(sys.argv[1], 0)
end = int(sys.argv[2], 0)
fn = sys.argv[3]
alg = sys.argv[4]

with open(fn, 'rb') as f:
  fw = f.read()

if end == 0:
    end = len(fw)

f_crc = fw[end-4:end]
real_crc = struct.unpack("!I", f_crc)[0]

print("f_crc =", f_crc, "real_crc =", real_crc)

#for i in range(2**32,2**33):
try:
    # crc32_func = crcmod.mkCrcFun(i, initCrc=0, xorOut=0)
    crc32_func = crcmod.predefined.Crc(alg)
    c1 = crc32_func.new()
    c2 = crc32_func.new()
    c1.update(fw[start:end])
    c2.update(fw[start:end-4])
    crc2 = c2.crcValue
    print("data CRC = ", crc2)
    c2.update(struct.pack("<I", crc2))
    print("full CRC = ", c2.digest())
    print("full CRC = ", c1.digest())
    if False:
        for i in range(start, end-4, 4):
            for j in range(end, start+4, -4):
                crc = crc32_func(fw[i:j])
#                if crc == 
except:
    print("died on")
    sys.exit(1)
#if i % 100000 == 0:
#   print("progress", i)



