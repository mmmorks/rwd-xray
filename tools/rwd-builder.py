#!/usr/bin/env python
import os
import struct
import binascii
import argparse

def param_to_data_string(param):
    # strip leading '0x'
    param = param.replace('0x','')
    # pad to even number of characters (required by binascii)
    if len(param) % 2 == 1:
        param = '0' + param
    return binascii.a2b_hex(param)

def generate_file_header(indicator, headers):
    header_bytes = indicator
    for header in headers:
        header_bytes += struct.pack('!B', len(header))
        for item in header:
            header_bytes += struct.pack('!B', len(item)) + item
    return header_bytes

def build(args):
    # convert from string to hex
    can_addr = param_to_data_string(args.can_address)
    fw_versions = list([(x.ljust(16, '\x00').encode('ascii')) for x in args.supported_versions])
    sa_keys = list(map(param_to_data_string, args.security_keys))
    fw_key = param_to_data_string(args.encryption_key)
    start_addr = param_to_data_string(args.start_address)
    data_size = param_to_data_string(args.data_size)

    f_dir = os.path.dirname(args.encrypted_file)
    f_base = os.path.splitext(os.path.basename(args.encrypted_file))[0]
    rwd_file = os.path.join(f_dir, f_base + '.rwd')

    indicator = b'\x5A\x0D\x0A' # CAN format
    headers = [
        [b'\x00'], # always zero
        [], # always empty
        [can_addr[2].to_bytes()], # significant byte in 29 bit addr (0x18da__f1)
        fw_versions, # previous firmware version(s)
        sa_keys, # security access key (one per prev firmware version)
        [fw_key], # firmware encryption key
    ]
    for i in range(len(headers)):
        print(('[{}]: {}'.format(i, headers[i])))
    print(('start = {} len = {}'.format(args.start_address, args.data_size)))

    rwd_header_bytes = generate_file_header(indicator, headers)
    with open(args.encrypted_file, 'rb') as f:
        rwd_fw_bytes = f.read()

    rwd_start_len = start_addr.rjust(4, b'\x00') + data_size.rjust(4, b'\x00')
    file_checksum = sum((rwd_header_bytes + rwd_start_len + rwd_fw_bytes)) & 0xFFFFFFFF
    #file_checksum = sum(rwd_header_bytes + rwd_start_len + rwd_fw_bytes) & 0xFFFFFFFF
    print(('file checksum: {}'.format(hex(file_checksum))))
    rwd_checksum_bytes = struct.pack('<L', file_checksum)

    with open(rwd_file, 'wb+') as f:
        f.write(rwd_header_bytes)
        f.write(rwd_start_len)
        f.write(rwd_fw_bytes)
        f.write(rwd_checksum_bytes)

    print("done!")

if __name__== "__main__":
    # example: python rwd-builder.py --can-address 0x18DA30F1 --supported-versions 12345-XXX-A030 12345-XXX-A040 --security-key 0x000100020003 0x000100020003 --encryption-key 0x0a0b0c --encrypted-file 12345-YYY-A030-M1.enc --start-address 0x0 --data-size 0x10000
    parser = argparse.ArgumentParser()
    parser.add_argument("--can-address", required=True, help="CAN address of ECU (e.g. 0x18DA30F1)")
    parser.add_argument("--supported-versions", required=True, nargs='+', help="software version(s) supported (e.g. 39990-TLA-A030")
    parser.add_argument("--security-keys", required=True, nargs='+', help="security key for each supported software version (e.g. 0x000100020003")
    parser.add_argument("--encryption-key", required=True, help="firmware encryption key (e.g. 0x010203)")
    parser.add_argument("--encrypted-file", required=True, help="encrypted firmware file (e.g. test.bin)")
    parser.add_argument("--start-address", required=True, help="address to start at in firmware file (e.g. 0x00)")
    parser.add_argument("--data-size", required=True, help="number of bytes to copy after start address (e.g. 0x10000)")
    args = parser.parse_args()
    build(args)
