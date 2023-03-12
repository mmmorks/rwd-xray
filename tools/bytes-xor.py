import sys

fn1 = sys.argv[1]
fn2 = sys.argv[2]

with open(fn1, 'rb') as f1, open(fn2, 'rb') as f2:
    fw1 = f1.read()
    fw2 = f2.read()

if len(fw1) != len(fw2):
    print("Files not same size")
    sys.exit(1)


out = bytearray(len(fw1))
for i in range(len(fw1)):
    out[i] = fw1[i] ^ fw2[i]

with open('out.bin', 'wb') as f:
    f.write(out)

