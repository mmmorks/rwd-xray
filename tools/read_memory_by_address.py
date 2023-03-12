from collections import namedtuple
import struct
import sys

MEMORY_LUT_DATA_A = b'\x10\xc4\xdf\xfe\x40\x00\x00\x00\x50\xc4\xdf\xfe\x20\x00\x00\x00\x70\xc4\xdf\xfe\x20\x00\x00\x00\x90\xc4\xdf\xfe\x20\x00\x00\x00\xb0\xc4\xdf\xfe\x20\x00\x00\x00\xf0\xc4\xdf\xfe\x20\x00\x02\x00\x10\xc5\xdf\xfe\x20\x00\x02\x00\x30\xc5\xdf\xfe\x20\x00\x02\x00\x50\xc5\xdf\xfe\x20\x00\x02\x00\x70\xc5\xdf\xfe\x20\x00\x02\x00\x90\xc5\xdf\xfe\xc0\x00\x02\x00\x50\xc6\xdf\xfe\x60\x00\x02\x00\xb0\xc6\xdf\xfe\xc0\x00\x02\x00\x70\xc7\xdf\xfe\x20\x00\x02\x00\x90\xc7\xdf\xfe\x20\x00\x02\x00\xb0\xc7\xdf\xfe\x20\x00\x02\x00\xd0\xc7\xdf\xfe\x20\x00\x02\x00\xf0\xc7\xdf\xfe\x00\x01\x02\x00\xf0\xc8\xdf\xfe\x40\x00\x02\x00\x30\xc9\xdf\xfe\x20\x00\x02\x00\x50\xc9\xdf\xfe\x20\x00\x03\x00\x70\xc9\xdf\xfe\x20\x00\x04\x00\xd0\xc4\xdf\xfe\x20\x00\x01\x00'
MEMORY_LUT_DATA_B = b'\x00\x00\x00\x00\x10\xc4\xdf\xfe\xc0\x00\x00\x00\x00\x02\x00\x00\xd0\xc4\xdf\xfe\x20\x00\x00\x00\x80\x02\x00\x00\xf0\xc4\xdf\xfe\x60\x04\x00\x00\x80\x3f\x00\x00\x50\xc9\xdf\xfe\x20\x00\x00\x00\xc0\x3f\x00\x00\x70\xc9\xdf\xfe\x20\x00\x00\x00'

MemLutA = namedtuple('mem_lut_a', 'start_addr num_bytes idx field3')
MemLutB = namedtuple('mem_lut_b', 'a b num_bytes field3 field4')

MEMORY_LUT_A = []
record_size = len(MEMORY_LUT_DATA_A) // 23
for i in range(0, 23):
    offset = i * record_size
    b = MEMORY_LUT_DATA_A[offset:offset+record_size]
    MEMORY_LUT_A.append(MemLutA._make(struct.unpack('<IHBc', b)))

MEMORY_LUT_B = []
record_size = len(MEMORY_LUT_DATA_B) // 5 
for i in range(0, 5):
    offset = i * record_size
    b = MEMORY_LUT_DATA_A[offset:offset+record_size]
    MEMORY_LUT_B.append(MemLutB._make(struct.unpack('<IIHcc', b)))

def UDS_do_memory_read_impl(req_start_addr, num_bytes, mode):
    if ((mode == 0) or (mode == 1)) or (mode == 3):
        if 0x580 < num_bytes + req_start_addr:
            print("Exceeded end address")
            return 1
    
        total_bytes = 0
        iVar2 = 0
        elem_addr = 0xfedfc410 + req_start_addr
        num_bytes_2 = num_bytes
        while True:
            idx = 0
            while True:
                end_addr = MEMORY_LUT_A[idx].start_addr + MEMORY_LUT_A[idx].num_bytes
                if not (elem_addr < MEMORY_LUT_A[idx].start_addr or (end_addr <= elem_addr)):
                    break
                idx = idx + 1
                if (0x16 < idx):
                    print("No match")
                    return 1
          
            idx = MEMORY_LUT_A[idx].idx
            start_addr_2 = elem_addr + (MEMORY_LUT_B[idx].a - MEMORY_LUT_B[idx].b) + 0x2000000
            start_addr_2 &= 0xffffffff
            if (idx == 2):
              start_addr_2 = start_addr_2 + 1 * 0xc00
            
            end_addr_2 = MEMORY_LUT_B[idx].num_bytes + start_addr_2
            if (end_addr <= elem_addr + num_bytes_2):
              num_bytes_2 = end_addr - elem_addr & 0xffff
           
            if (mode == 0):
              UDS_do_memory_read_mode_0_1_2(start_addr_2,num_bytes_2)
            
            elif (mode == 1):
              UDS_do_memory_read_mode_0_1_2(end_addr_2,num_bytes_2)
            
            else:
              iVar1 = UDS_do_memory_read_mode_3(start_addr_2,end_addr_2,num_bytes_2)
              iVar2 = (iVar1 == 1) + iVar2 * (iVar1 != 1)
            
            total_bytes = total_bytes + num_bytes_2 & 0xffff
            if (num_bytes <= total_bytes): break
            idx = (num_bytes - total_bytes) * (0 < (num_bytes - total_bytes))
            num_bytes_2 = 0xffff
            if (idx < 0x10000):
              num_bytes_2 = idx * (idx != 0)
            
            num_bytes_2 = num_bytes_2 & 0xffff
            elem_addr = end_addr
          
            if (iVar2 != 0):
                return 1
          
      
    else:
        if (0x4000 < num_bytes + req_start_addr):
            return 1
    
        UDS_do_memory_read_mode_0_1_2(req_start_addr + 0x2000000,num_bytes)
  
    return 0

def UDS_routine_control_read_memory_mode_3(start_addr, num_bytes):
    s = (start_addr + 0xf0000000) & 0xffffffff
    UDS_do_memory_read_impl(s, num_bytes, 3)

def UDS_do_memory_read_mode_0_1_2(start_addr, num_bytes):
    print("UDS_do_memory_read_mode_0_1_2 invoked with start_addr = {}, num_bytes = {}".format(hex(start_addr), num_bytes))

def UDS_do_memory_read_mode_3(start_addr, end_addr, num_bytes):
    print("UDS_do_memory_read_mode_3 invoked with start_addr = {}, end_addr = {}, num_bytes = {}".format(hex(start_addr), hex(end_addr), num_bytes))

start_addr = int(sys.argv[1], 0)
num_bytes = int(sys.argv[2], 0)
mode = int(sys.argv[3], 0)

if mode == 3:
    rc = UDS_routine_control_read_memory_mode_3(start_addr, num_bytes)
else:
    rc = UDS_do_memory_read_impl(start_addr, num_bytes, mode)

sys.exit(rc)
