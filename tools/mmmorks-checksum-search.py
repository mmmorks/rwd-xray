import sys
import binascii
import struct
import crcmod

def add_crc(c):
    return (c, crcmod.predefined.Crc(c))

def calc_crc(fw, crcs, start, end):
    WINDOW = 4
    checksum = fw[end:end+WINDOW].hex().upper()
    print("calc_crc. checksum:", checksum)
    for name, i in crcs:
        x = i.new()
        for a in range(start, end, WINDOW):
            b = bytearray(fw[a:a+WINDOW])
            b.reverse()
            x.update(b)

        if x.hexdigest().find(checksum) >= 0:
            print("crc: ", x.hexdigest(), "name:", name)

PADDING_BYTES = [0xFF]
# first param is start addr (e.g. 0x4000)
start = int(sys.argv[1], 0)
end = int(sys.argv[2], 0)
# second param is firmware file name
fn = sys.argv[3]
window = 4
num_bits = window * 8
mask = 2 ** num_bits - 1
format_str = '0' + str(num_bits) + 'b'
print("mask", hex(mask))

crc16 = []
crc16.append(add_crc('crc-16'))
crc16.append(add_crc('crc-16-buypass'))
crc16.append(add_crc('crc-16-dds-110'))
crc16.append(add_crc('crc-16-dect'))
crc16.append(add_crc('crc-16-dnp'))
crc16.append(add_crc('crc-16-en-13757'))
crc16.append(add_crc('crc-16-genibus'))
crc16.append(add_crc('crc-16-maxim'))
crc16.append(add_crc('crc-16-mcrf4xx'))
crc16.append(add_crc('crc-16-riello'))
crc16.append(add_crc('crc-16-t10-dif'))
crc16.append(add_crc('crc-16-teledisk'))
crc16.append(add_crc('crc-16-usb'))
crc16.append(add_crc('x-25'))
crc16.append(add_crc('xmodem'))
crc16.append(add_crc('modbus'))
crc16.append(add_crc('kermit'))
crc16.append(add_crc('crc-ccitt-false'))
crc16.append(add_crc('crc-aug-ccitt'))

crc32 = []
crc32.append(add_crc('crc-32'))
crc32.append(add_crc('crc-32-bzip2'))
crc32.append(add_crc('crc-32c'))
crc32.append(add_crc('crc-32d'))
crc32.append(add_crc('crc-32-mpeg'))
crc32.append(add_crc('posix'))
crc32.append(add_crc('crc-32q'))
crc32.append(add_crc('jamcrc'))
crc32.append(add_crc('xfer'))

if window == 2:
    pack_str = "!H"
    crc = crc16
elif window == 4:
    pack_str = "!I"
    crc = crc32

sumloc = int(sys.argv[4], 0)
xorloc = int(sys.argv[5], 0)
padding_threshold = int(sys.argv[6], 0)

with open(fn, 'rb') as f:
  fw = f.read()


if end == -1: end = len(fw)
f_bytes = fw[sumloc:sumloc+window]
hex_str = f_bytes.hex().upper()
print("file checksum =", hex_str, "checksum bytes = ", f_bytes)


last_byte = b"\xFF"
padding = False
startpos = start
for i in range(start, end+1):
    curr_byte = fw[i]
    if curr_byte != last_byte:
        if padding and i - startpos > padding_threshold and i % window == 0:
            print("i =", hex(i).upper(), "size =", i-startpos, "last_byte =", hex(last_byte).upper(), "curr_byte =", hex(curr_byte).upper(), "afterbytes:", fw[i:i+window].hex().upper())
            calc_crc(fw, crc32, start, i)

        padding = curr_byte in PADDING_BYTES
        last_byte = curr_byte
        startpos = i
        
sumt = 0
xort = 0
for i in range(start, end-window, window):
    if i == sumloc or i == xorloc: continue
    b = struct.unpack(pack_str, fw[i:i+window])[0] 
    xort ^= b
    sumt += b
    sumt &= mask
#    print(i, sumt)

sumhex = struct.pack(pack_str, sumt).hex().upper()
xorhex = struct.pack(pack_str, xort).hex().upper()

print('file checksum =', hex_str, 'sum =', sumhex, 'xor =', xorhex)
