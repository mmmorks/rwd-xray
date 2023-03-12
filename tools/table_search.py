import os
import sys
import binascii
import argparse
import struct

parser = argparse.ArgumentParser()
parser.add_argument("-bytes", required=True, help="Table row length in bytes")
parser.add_argument("-rows", required=True, help="Number of rows in table")
args = parser.parse_args()

def main():
    with open(os.path.join(sys.path[0], "user.bin"), "rb+") as input_bin:
        cur_pos = 0
        len = int(args.bytes)
        rows = int(args.rows)
        excludes = [
        b'6265622d352c6265622d352c6265622d352c',
        b'ffffffffffffffffffffffffffffffffffff',
        b'000000000000000000000000000000000000',
        b'65622d352c6265622d352c6265622d352c62',
        b'622d352c6265622d352c6265622d352c6265',
        b'2d352c6265622d352c6265622d352c626562',
        b'352c6265622d352c6265622d352c6265622d',
        b'2c6265622d352c6265622d352c6265622d35'
        ]
        format = '!' + str(len // 2) + 'H'
        for i in input_bin:
            dat = [0]*rows
            begins_zero = True
            monotonic = True
            for j in range(0, rows):
                input_bin.seek(cur_pos + j*len)
                dat[j] = struct.unpack_from(format, input_bin.read(len))
                if dat[j][0] != 0:
                   begins_zero = False
                else:
                   last = dat[j][0]
                   for q in dat[j][1:]:
                       if q - last < 0:
                           monotonic = False
                       last = q;
#                   print('monotonic: {} data: {}'.format(monotonic, dat[j]))
                   
            if begins_zero and monotonic:
                print("Match! Address: {}".format(hex(cur_pos)))
                for x in dat:
                    s = binascii.hexlify(struct.pack(format, *x))
                    print(x)
                    #if s not in excludes:
                    #    print("Match! Address: {} Hex: {} Data: {}".format(hex(cur_pos), s, x))
            cur_pos = cur_pos + 1
main()
