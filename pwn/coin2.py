from pwn import *
from string import *
import re

conn = remote('pwnable.kr', 9008)
b = conn.recvuntil("sec ... -\n")
conn.recvuntil("\n")

def gen(N, C):
	groups = []
	for i in range(C):
		groups.append([])

	for i in range(N):
		for bit in range(C):
			if ((i >> bit) & 1) == 1:
				groups[bit].append(str(i))
	return "-".join(" ".join(group) for group in groups) + "\n"

while True:
	b = conn.recvuntil("\n")
	if b.startswith("N="):
		mid = b.split("=")
		N, C = int(mid[1].split(" ")[0]), int(mid[2].split("\n")[0])
		#print "[*] N : %d, C : %d" % (N, C)
		binary = gen(N, C)
		#print binary
		conn.send(binary)

	elif re.match(r"^[0-9\-]+", b) is not None:
		result, idx = 0, 1
		weights = [int(x) for x in b.split("-")]
		for i, w in enumerate(weights):
			if w % 10 != 0:
				result += idx
			idx = idx * 2

		conn.send(str(result) + "\n")
		b = conn.recvuntil("\n")
		print b

	else:
		print b

conn.close()