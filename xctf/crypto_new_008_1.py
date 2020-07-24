import libnum

p = 473398607161
q = 4511491
e = 17
N = (p - 1) * (q - 1)

d = libnum.invmod(e, N)

print(d)

