from socket import *
from z3 import *
import time, struct, telnetlib
import re

def recvuntil(t):
	data = ''
	while not data.endswith(t):
		tmp = s.recv(1)
		if not tmp: break
		data += tmp
	return data

def comm(flag, x1, y1, val):
	if flag == 1:
		command = ""
		for i in range(0, len(x1)):
			command += "X[%d][%d] + " % (int(x1[i])-1, int(y1[i])-1)
		command = command[0:len(command)-3] + " > %d" % (val)
	else:
		command = ""
		for i in range(0, len(x1)):
			command += "X[%d][%d] + " % (int(x1[i])-1, int(y1[i])-1)
		command = command[0:len(command)-3] + " < %d" % (val)
	return command

def solve_func(flag, x1, y1, val):
	X = [[Int("x_%s_%s" % (i+1, j+1)) for j in range(9) ] for i in range(9) ]
	st = comm(flag, x1, y1, val)
	exec "cells_c = [ And(1 <= X[i][j], X[i][j] <= 9, %s) for i in range(9) for j in range(9) ]" % (st)

	rows_c = [Distinct(X[i]) for i in range(9) ]
	cols_c = [Distinct([ X[i][j] for i in range(9) ]) for j in range(9) ]
	sq_c = [Distinct([ X[3*i0 + i][3 * j0 + j] for i in range(3) for j in range(3) ]) for i0 in range(3) for j0 in range(3) ]
	sudoku_c = cells_c + rows_c + cols_c + sq_c
	instance_c = [ If(instance[i][j] == 0, True, X[i][j] == instance[i][j]) for i in range(9) for j in range(9) ]
	return X, cells_c, rows_c, cols_c, sq_c, sudoku_c, instance_c

pattern = r'(\d+[,]\d+)'
s = socket(AF_INET, SOCK_STREAM)
s.connect(('pwnable.kr', 9016))
data = recvuntil("to see example.\n")
s.send("\n")
data = recvuntil("start game\n")
s.send("\n")
chk = 1
while True:
	flag = 0
	x, y = [], []
	r = re.compile(pattern)
	data = recvuntil("solution? : \n")
	print data
	puzzle = data.split("Stage")[1][4:255]
	if chk == 100:
		puzzle = data.split("Stage")[1][4:256]
	puzzle = puzzle.replace("\n", ",")
	puzzle = puzzle.replace("[", "(")
	puzzle = puzzle.replace("]", ")")
	if "bigger" in data:
		flag = 1
	else:
		flag = 0

	val = int((data.split("than ")[1]).split("\n")[0])
	rules = data.split(":")[1:]
	for i in range(0, len(rules)-1):
		match = r.search(rules[i])
		buf = match.group(0)
		buf = buf.split(",")
		x.append(int(buf[0]))
		y.append(int(buf[1]))

	if puzzle[0] == ",":
		puzzle = puzzle[1:]
		if puzzle[0] == ",":
			puzzle = puzzle[1:]
		puzzle += ")"
	if chk == 100:
		print puzzle
	command = "instance = (%s)"%(puzzle)
	print chk
	exec command

	X, cells_c, rows_c, cols_c, sq_c, sudoku_c, instance_c = solve_func(flag, x, y, val)
	sol = Solver()
	sol.add(sudoku_c + instance_c)
	if sol.check() == sat:
		m = sol.model()
		r = [ [ m.evaluate(X[i][j]) for j in range(9) ] for i in range(9) ]
		result = r
		print_matrix(r)
		s.send(str(result) + "\n")
		if chk == 100:
			time.sleep(1)
			print "--- print ---"
			print s.recv(4096)
		chk += 1
	else:
		print "fail.."