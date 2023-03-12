import sys
import binascii
import struct

def sum_dwords(b):
    s = 0
    for i in range(0, len(b)//4):
        s += (b[i*4] << 0) + (b[i*4+1] << 8) + (b[i*4+2] << 16) + (b[i*4+3] << 24) # little endian
        s &= 0xFFFFFFFF

    return s

start = int(sys.argv[1], 0)
end = int(sys.argv[2], 0)
fn = sys.argv[3]

with open(fn, 'rb') as f:
  fw = f.read()

if end == 0:
    end = len(fw)

f_chk = fw[end-4:end]

print("f_chk = ", f_chk.hex())

try:
    c1 = (-sum_dwords(fw[start:end-4])) & 0xFFFFFFFF
    c2 = sum_dwords(fw[start:end]) & 0xFFFFFFFF
    chk = struct.pack("<I", c1)
    chk2 = struct.pack("<I", c2)
    print("sum = {}".format(chk.hex()))
    print("sum = {}, hex = {}".format(c2, chk2.hex()))
except:
    print("died on")
    raise
    sys.exit(1)



