import sys

# XOR Keys
keys = [0x57, 0x77, 0x36]

argvs = sys.argv
if len(sys.argv) != 2:
    print("Usage: decrypt-dat.py <target enc file>")
    sys.exit(1)

fname = sys.argv[1]
with open(fname, 'rb') as input_file:
    data = input_file.read()

decrypted_data = bytearray()

for i, byte in enumerate(data):
    key = keys[i % len(keys)]
    if (i % len(keys)) == 2:
        decrypted_byte = (i ^ byte ^ key) & 0xFF
    else:
        decrypted_byte = byte ^ key
    decrypted_data.append(decrypted_byte)

with open(fname + '_dec.dat', 'wb') as output_file:
    output_file.write(decrypted_data)
