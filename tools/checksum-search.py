import sys
import binascii
import struct

# first param is start addr (e.g. 0x4000)
start = int(sys.argv[1], 0)
end = int(sys.argv[2], 0)
# second param is firmware file name
fn = sys.argv[3]

with open(fn, 'rb') as f:
  fw = f.read()
  
if end == -1: end = len(fw)
checksum_1 = 0  # sum(x)
checksum_2 = 0  # -sum(x)
checksum_3 = 0  # xor(x)
for i in range(start, end-2, 2):
  bytes_1 = struct.unpack('!H', fw[i:i+2])[0]
  checksum_1 += bytes_1
  checksum_2 -= bytes_1
  checksum_3 ^= bytes_1
  checksum_1_packed = struct.pack('!H', checksum_1 & 0xFFFF)
  checksum_2_packed = struct.pack('!H', checksum_2 & 0xFFFF)
  checksum_3_packed = struct.pack('!H', checksum_3)
  if i > 2 and checksum_1_packed in (fw[i+2:i+4], fw[i+4:i+6]):
    print("Checksum by sum found: {} at {}".format(checksum_1_packed.hex(), hex(i+2)))
  if i > 2 and checksum_2_packed in (fw[i+2:i+4], fw[i+4:i+6]):
    print("Checksum by -sum found: {} at {}".format(checksum_2_packed.hex(), hex(i+2)))
  if i > 2 and checksum_3_packed in (fw[i+2:i+4], fw[i+4:i+6]):
    print("Checksum by xor found: {} at {}".format(checksum_3_packed.hex(), hex(i+2)))

# end = 0x4e5ec
# struct.pack('!H', sum([struct.unpack('!H', fw[addr:addr+2])[0] for addr in range(0x4000, end, 2)]) & 0xFFFF)
