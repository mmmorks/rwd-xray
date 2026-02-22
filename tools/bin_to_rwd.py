#!/usr/bin/env python
#
# Convert full firmware binary to rwd patch.
# Supported models:
#   CR-V 5g (part num: 39990-TLA), tested
#   Civic 2016 sedan (part num: 39990-TBA), tested
#   Civic 2016 hatchback Australia (part num: 39990-TEA), tested
#   Civic 2016 hatchback (part num: 39990-TGG), tested
#
import os
import sys
import argparse
import subprocess
import struct
import collections
rwd_builder = __import__("rwd-builder")

# Decryption lookup table built from Civic 2016 sedan bin/rwd, also apply to CR-V 5g.
default_decrypt_lookup_table = {5: 1, 0: 0, 128: 128, 127: 127, 255: 255, 248: 248, 251: 251, 4: 4, 129: 125, 10: 6, 15: 15, 75: 75, 74: 70, 29: 25, 14: 10, 94: 90, 3: 3, 6: 2, 9: 5, 7: 7, 8: 8, 13: 9, 11: 11, 12: 12, 17: 13, 18: 14, 16: 16, 21: 17, 22: 18, 19: 19, 20: 20, 25: 21, 34: 30, 26: 22, 23: 23, 24: 24, 30: 26, 27: 27, 28: 28, 33: 29, 100: 100, 143: 143, 159: 159, 171: 171, 81: 77, 37: 33, 38: 34, 35: 35, 48: 48, 222: 218, 149: 145, 228: 228, 90: 86, 88: 88, 124: 124, 163: 163, 152: 152, 164: 164, 32: 32, 169: 165, 170: 166, 176: 176, 208: 208, 238: 234, 36: 36, 64: 64, 98: 94, 240: 240, 239: 239, 219: 219, 111: 111, 172: 172, 84: 84, 196: 196, 132: 132, 192: 192, 77: 73, 191: 191, 146: 142, 118: 114, 51: 51, 89: 85, 178: 174, 1: 253, 92: 92, 137: 133, 250: 246, 121: 117, 158: 154, 67: 67, 216: 216, 203: 203, 79: 79, 247: 247, 177: 173, 249: 245, 195: 195, 244: 244, 243: 243, 135: 135, 246: 242, 185: 181, 245: 241, 221: 217, 242: 238, 236: 236, 230: 226, 235: 235, 150: 146, 237: 233, 232: 232, 231: 231, 184: 184, 233: 229, 227: 227, 99: 99, 229: 225, 218: 214, 223: 223, 62: 58, 226: 222, 144: 144, 220: 220, 215: 215, 217: 213, 211: 211, 102: 98, 213: 209, 83: 83, 207: 207, 57: 53, 209: 205, 200: 200, 141: 137, 202: 198, 197: 193, 109: 105, 188: 188, 190: 186, 183: 183, 182: 178, 175: 175, 71: 71, 140: 140, 174: 170, 206: 202, 167: 167, 166: 162, 145: 141, 156: 156, 180: 180, 157: 153, 154: 150, 147: 147, 66: 62, 101: 97, 139: 139, 136: 136, 134: 130, 53: 49, 106: 102, 126: 122, 119: 119, 116: 116, 43: 43, 108: 108, 110: 106, 103: 103, 105: 101, 96: 96, 97: 93, 50: 46, 91: 91, 214: 210, 56: 56, 252: 252, 85: 81, 204: 204, 73: 69, 69: 65, 63: 63, 60: 60, 61: 57, 55: 55, 78: 74, 52: 52, 54: 50, 93: 89, 47: 47, 65: 61, 49: 45, 46: 42, 45: 41, 40: 40, 39: 39, 254: 250, 41: 37, 31: 31, 70: 66, 162: 158, 205: 201, 153: 149, 87: 87, 42: 38, 44: 44, 58: 54, 59: 59, 68: 68, 72: 72, 76: 76, 82: 78, 80: 80, 86: 82, 95: 95, 104: 104, 107: 107, 113: 109, 114: 110, 112: 112, 117: 113, 115: 115, 122: 118, 120: 120, 125: 121, 123: 123, 130: 126, 133: 129, 131: 131, 138: 134, 142: 138, 148: 148, 151: 151, 155: 155, 161: 157, 160: 160, 165: 161, 168: 168, 173: 169, 181: 177, 179: 179, 186: 182, 189: 185, 187: 187, 193: 189, 194: 190, 198: 194, 201: 197, 199: 199, 210: 206, 212: 212, 225: 221, 224: 224, 234: 230, 241: 237, 253: 249, 2: 254}

# sum of x, x is unsigned shorts
def checksum_by_sum(fw, start, end):
  s = 0
  for i in range(start, end, 2):
    s += struct.unpack('!H', fw[i:i + 2])[0]
  return s


# sum of -x, x is unsigned shorts
def checksum_by_negative_sum(fw, start, end):
  s = 0
  for i in range(start, end, 2):
    s += -struct.unpack('!H', fw[i:i + 2])[0]
  return s

# sum of -x, x is little endian unsigned ints 
def checksum_by_negative_sum_little_endian_ints(fw, start, end):
  s = 0
  for i in range(start, end, 4):
    s -= struct.unpack('<I', fw[i:i + 4])[0]
  return s


checksum_funcs = [checksum_by_sum, checksum_by_negative_sum, checksum_by_negative_sum_little_endian_ints]

# E4 torque LUT: 256-entry nonlinear curve (512 bytes, LE ushorts, max 5120)
_E4_LUT_OLD = bytes.fromhex(
    '00003a007300ad00e70021015a019401ce01080241027b02b502ef0228036203'
    '9c03d6030f0449048304bd04f60430056a05a405dd05170651068b06c406fe06'
    '38075d078207a707cc07f10716083b0860088408a908ce08f30818093d096209'
    '8709ac09d109f6091b0a400a650a8a0aaf0ad30af80a1d0b420b670b8c0bb10b'
    'd60bfb0b0f0c220c360c4a0c5d0c710c850c980cac0cc00cd40ce70cfb0c0f0d'
    '220d360d4a0d5d0d710d850d980dac0dc00dd30de70dfb0d0f0e220e360e4a0e'
    '5d0e710e850e980eac0ec00ed30ee70efb0e0e0f220f360f4a0f5d0f710f850f'
    '980fac0fc00fd30fe70ffb0f0e102210361049105d10711085109810ac10c010'
    'd310e710fb100e112211361149115d11711184119811ac11c011d311e711fb11'
    '0e122212361249125d12711284129812ac12bf12d312e712fb120e1322133613'
    '49135d1365136d1375137d1385138e1396139e13a613ae13b613be13c613ce13'
    'd613df13e713ef13f713ff13ff13ff1300140014001400140014001400140014'
    '0014001400140014001400140014001400140014001400140014001400140014'
    '0014001400140014001400140014001400140014001400140014001400140014'
    '0014001400140014001400140014001400140014001400140014001400140014'
    '0014001400140014001400140014001400140014001400140014001400140014')
# E4 torque LUT: extended-slope + quadratic rolloff (max 10246, ~2× authority)
# Stock [0-65], transition 37→42/idx [66-100], linear 42/idx [100-221], rolloff [221-255]
_E4_LUT_NEW = bytes.fromhex(
    '00003a007300ad00e70021015a019401ce01080241027b02b502ef0228036203'
    '9c03d6030f0449048304bd04f60430056a05a405dd05170651068b06c406fe06'
    '38075d078207a707cc07f10716083b0860088408a908ce08f30818093d096209'
    '8709ac09d109f6091b0a400a650a8a0aaf0ad30af80a1d0b420b670b8c0bb10b'
    'd60bfb0b200c450c6b0c900cb60cdc0c020d280d4e0d740d9b0dc10de80d0f0e'
    '360e5d0e850eac0ed40efc0e240f4c0f740f9c0fc50fed0f16103f1068109110'
    'bb10e4100e11381162118c11b611e0110a1234125e128812b212dc1206133013'
    '5a138413ae13d81302142c1456148014aa14d414fe14281552157c15a615d015'
    'fa1524164e167816a216cc16f61620174a1774179e17c817f2171c1846187018'
    '9a18c418ee18181942196c199619c019ea19141a3e1a681a921abc1ae61a101b'
    '3a1b641b8e1bb81be21b0c1c361c601c8a1cb41cde1c081d321d5c1d861db01d'
    'da1d041e2e1e581e821eac1ed61e001f2a1f541f7e1fa81fd21ffc1f26205020'
    '7a20a420ce20f82022214c217621a021ca21f4211e22482272229c22c622f022'
    '1a2344236e239823c223ec23162440246a249424be24e82412253c2565258d25'
    'b425da25fe252126432664268326a226bf26db26f5260e2727273d2753276727'
    '7b278c279d27ad27bb27c827d327de27e727ef27f627fc270028032805280628')

car_models = {
  '39990-TLA-A030': { #CR-V thanks to joe1
    'can-address': '0x18DA30F1',
    'supported-versions': ['39990-TLA-A030',  '39990-TLA-A040', '39990-TLA,A030',  '39990-TLA,A040'],
    'security-key': ['0x011101121120', '0x011101121120', '0x011101121120', '0x011101121120'],
    'encryption-key':  '0x010203',
    'start-address': 0x4000,
    'data-size': 0x6c000,
    # (checksum func idx, offset)
    'checksum-offsets': [(0, 0x6bf80), (1, 0x6bffe)] #original bin checksums are 0x419b at offset 0x6FF80 and 0x24ef at 0x6FFFE, but since we start the bin from 0x4000 after bootloader, we offset the checksum accordingly
  },

  '39990-TBA-A030': { #civic sedan thanks to mystery leaker

    'can-address': '0x18DA30F1',
    'supported-versions': ['39990-TBA-A000', '39990-TBA-A010', '39990-TBA-A020', '39990-TBA-A030'],
    'security-key': ['0x011100121020', '0x011100121020', '0x011101121120', '0x011101121120'],
    'encryption-key':  '0x010203',
    'start-address': 0x4000,
    'data-size': 0x4c000,
    # (checksum func idx, offset)
    'checksum-offsets': [(0, 0x4bf80), (1, 0x4bffe)] #original bin checksums are 0xDD23 at offset 0x4FF80 and 0xEDDF at 0x4FFFE, but since we start the bin from 0x4000 after bootloader, we offset the checksum accordingly
  },

  '39990-TEA-T330': { #civic hatch au thanks to ming
    'can-address': '0x18DA30F1',
    'supported-versions': ['39990-TEA-T330'],
    'security-key': ['0x011101121120'],
    'encryption-key': '0x010203',
    'start-address': 0x4000,
    'data-size': 0x4c000,
    # (checksum func idx, offset)
    'checksum-offsets': [(0, 0x4bf80), (1, 0x4bffe)]
  },

  '39990-TGG-A120': { #civic hatch thanks to R3DLOBST3R
    'can-address': '0x18DA30F1',
    'supported-versions': ['39990-TGG-A120'],
    'security-key': ['0x011101121120'],
    'encryption-key': '0x010203',
    'start-address': 0x4000,
    'data-size': 0x4c000,
    # (checksum func idx, offset)
    'checksum-offsets': [(0, 0x4bf80), (1, 0x4bffe)]
  },

   '39990-TRW-A020': { #clarity thanks to wirelessnet2
     'can-address': '0x18DA30F1',
     'supported-versions': ['39990-TRW-A010', '39990-TRW-A020', '39990-TRW,A010', '39990-TRW,A020'],
     'security-key': ['0x011101121120', '0x011101121120', '0x011101121120', '0x011101121120'],
     'encryption-key': '0x010203',
     'start-address': 0x4000,
     'data-size': 0x4c000,
      #(checksum func idx, offset)
     'checksum-offsets': [(0, 0x4bf80), (1, 0x4bffe)]
  },
   '39990-TG7-A030': { #pilot mmmorks
     'can-address': '0x18DA30F1',
     'supported-versions': ['39990-TG7-A020', '39990-TG7-A030'], #'39990-TG7,A020', '39990-TG7,A030'],
     'security-key': ['0x001100121020', '0x001100121020'],
     'encryption-key': '0x010203',
     'start-address': 0x10000,
     'data-size': 0x50000,
      #(checksum func idx, offset)
     'checksum-offsets': [(2, 0x9ffc, '<I'), (2, 0x1cffc, '<I'), (2, 0x4fefc, '<I')]
  },
   '39990-TG7-A060': { #pilot mmmorks
     'can-address': '0x18DA30F1',
     'supported-versions': ['39990-TG7-A060'], #, '39990-TG7,A060'],
     'security-key': ['0x001100121020'], #, '0x001100121020'],
     'encryption-key': '0x010203',
     'start-address': 0x10000,
     'data-size': 0x50000,
      #(checksum func idx, offset)
     'checksum-offsets': [(2, 0x9ffc, '<I'), (2, 0x1cffc, '<I'), (2, 0x4fefc, '<I')],
     'patches': [
       (0x0f22b, b'\x14', b'\x01'), # min_speed_1
       (0x100ad, b'\x14', b'\x01'), # min_speed_1
       (0x10f2f, b'\x14', b'\x01'), # min_speed_1
       (0x11db1, b'\x14', b'\x01'), # min_speed_1
       (0x12c33, b'\x14', b'\x01'), # min_speed_1
       (0x1bdb8, b'\x0a', b'\x01'), # min_speed_2
       (0x1c030, b'\x0a', b'\x01'), # min_speed_2
       (0x1c2a8, b'\x0a', b'\x01'), # min_speed_2
       (0x1c520, b'\x0a', b'\x01'), # min_speed_2
       (0x1c798, b'\x0a', b'\x01'), # min_speed_2
       # E4 torque path: extended-slope + quadratic rolloff (~2x authority)
       # All 5 lane_assist_params variants: torque_lut, correction_gain, clamps
       # Offsets are into .bin data (Ghidra address - 0x10000)
       # Variant 4 (idx=5): TG8A2, TG8X0 — Ghidra base 0x1E5AA
       (0x0E9D0, _E4_LUT_OLD, _E4_LUT_NEW),              # torque_lut[256] extended-slope
       (0x0F1DE, b'\x00\xa0', b'\x00\xbe'),               # correction_gain_max 0xA000→0xBE00
       (0x0F222, b'\x80', b'\xbe'),                       # component_x_max_limit 128→190
       (0x0F223, b'\xa0', b'\xbe'),                       # component_b_max_limit 160→190
       (0x0F224, b'\x99\x01', b'\xe6\x01'),               # component_d_max_limit 409→486
       # Variant 3 (idx=4): TG8C0, TG8A0, TG8A1, TG8C1 — Ghidra base 0x1F42C
       (0x0F852, _E4_LUT_OLD, _E4_LUT_NEW),              # torque_lut[256] extended-slope
       (0x10060, b'\x00\xa0', b'\x00\xbe'),               # correction_gain_max 0xA000→0xBE00
       (0x100A4, b'\x80', b'\xbe'),                       # component_x_max_limit 128→190
       (0x100A5, b'\xa0', b'\xbe'),                       # component_b_max_limit 160→190
       (0x100A6, b'\x99\x01', b'\xe6\x01'),               # component_d_max_limit 409→486
       # Variant 2 (idx=3): TG7D0, TG7Y0, TG7C2, TG7A2 — Ghidra base 0x202AE
       (0x106D4, _E4_LUT_OLD, _E4_LUT_NEW),              # torque_lut[256] extended-slope
       (0x10EE2, b'\x00\xa0', b'\x00\xbe'),               # correction_gain_max 0xA000→0xBE00
       (0x10F26, b'\x80', b'\xbe'),                       # component_x_max_limit 128→190
       (0x10F27, b'\xa0', b'\xbe'),                       # component_b_max_limit 160→190
       (0x10F28, b'\x99\x01', b'\xe6\x01'),               # component_d_max_limit 409→486
       # Variant 1 (idx=2): TG7C0, TG7A0, TG7C1, TG7A1 — Ghidra base 0x21130
       (0x11556, _E4_LUT_OLD, _E4_LUT_NEW),              # torque_lut[256] extended-slope
       (0x11D64, b'\x00\xa0', b'\x00\xbe'),               # correction_gain_max 0xA000→0xBE00
       (0x11DA8, b'\x80', b'\xbe'),                       # component_x_max_limit 128→190
       (0x11DA9, b'\xa0', b'\xbe'),                       # component_b_max_limit 160→190
       (0x11DAA, b'\x99\x01', b'\xe6\x01'),               # component_d_max_limit 409→486
       # Variant 0 (idx=1/default): fallback — Ghidra base 0x21FB2
       (0x123D8, _E4_LUT_OLD, _E4_LUT_NEW),              # torque_lut[256] extended-slope
       (0x12BE6, b'\x00\xa0', b'\x00\xbe'),               # correction_gain_max 0xA000→0xBE00
       (0x12C2A, b'\x80', b'\xbe'),                       # component_x_max_limit 128→190
       (0x12C2B, b'\xa0', b'\xbe'),                       # component_b_max_limit 160→190
       (0x12C2C, b'\x99\x01', b'\xe6\x01'),               # component_d_max_limit 409→486
     ]
  },
}

def apply_patches(fw, apply_patches, car):
  patch_fw = bytearray(fw)
  if apply_patches:
    if not 'patches' in car:
      raise Exception('apply_patches = true, but there are no patches for this model')

    for offset, old, new in car['patches']:
      print('Patching {:08x} from {} to {}'.format(offset, old, new))
      assert len(old) == len(new)
      length = len(old)
      assert patch_fw[offset:offset+length] == old, 'Expected {}, but got {}'.format(old, patch_fw[offset:offset+length])
      patch_fw[offset:offset+length] = new

  return patch_fw

def main():
  # example: python3 bin_to_rwd.py --input_bin crv_5g_user_patched.bin --model 39990-TLA-A030
  parser = argparse.ArgumentParser()
  parser.add_argument("--input_bin", required=True, help="Full firmware binary file")
  parser.add_argument("--model", required=True, help="EPS part number")
  parser.add_argument("--patch", action='store_true', help="Apply patches before RWD generation")
  args = parser.parse_args()

  if not args.model in car_models:
    print('Car model %s not found' % args.model)
    sys.exit(-1)

  print('Creating rwd for model %s' % args.model)
  m = car_models[args.model]
  if not os.path.exists(args.input_bin):
    print('%s not found' % args.input_bin)
    sys.exit(-1)

  encrypt_lookup_table = {}
  for k, v in default_decrypt_lookup_table.items():
    encrypt_lookup_table[v] = k

  with open(args.input_bin, 'rb') as f:
    full_fw = f.read()
  
  patch_fw = apply_patches(full_fw, args.patch, m)

  start = 0
  for func_idx, off, format_str in m['checksum-offsets']:
    s = format_str[1].lower()
    if s == 'h':
        size = 2
    elif s == 'i':
        size = 4
    else:
        raise Exception("Unexpected format_str")

    mask = 2 ** (size*8) - 1
    old_checksum = struct.unpack(format_str, patch_fw[off:off+size])[0] & mask
    new_checksum = checksum_funcs[func_idx](patch_fw, start, off) & mask
    start = off+size
    if old_checksum != new_checksum:
      print('Update checksum at offset %s from %s to %s' % (hex(off),  hex(old_checksum), hex(new_checksum)))
      patch_fw = patch_fw[:off] + struct.pack(format_str, new_checksum & mask) + patch_fw[start:]
    else:
      print('Checksum at %s unchanged' % (hex(off)))

  encrypted = bytearray()
  for b in patch_fw:
    encrypted.append(encrypt_lookup_table[b])
  out_enc_path = args.input_bin + '.enc'
  with open(out_enc_path, 'wb') as out_f:
    out_f.write(encrypted)
    print('Encryption done, saved to %s.' % out_enc_path)

  BuilderArgs = collections.namedtuple('BuilderArgs', 'can_address supported_versions security_keys encryption_key encrypted_file start_address data_size')
  args = BuilderArgs(can_address=m['can-address'],
                     supported_versions=m['supported-versions'],
                     security_keys=m['security-key'],
                     encryption_key=m['encryption-key'],
                     encrypted_file=out_enc_path,
                     start_address=hex(m['start-address']),
                     data_size=hex(m['data-size']))

  rwd_builder.build(args)
  print('RWD file %s created.' % (out_enc_path[:-4] + '.rwd'))

if __name__== "__main__":
    main()
