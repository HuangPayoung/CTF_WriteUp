# RCTF 

日常自闭摸了一道musl，Nu1L战队有点强啊直接ak了，复现他们的WP。剩下两道太难了实在不想逆向，先咕了。

# 题目列表

## catch_the_frog


## ezheap

edit和show的时候，虽然检查了element_idx，但是没有检查idx。

### 攻击思路
1. 利用bss段上stdin泄露libc基址。
2. 进行FSOP攻击，改掉虚表。

## game

这题属实恶心，有点像vm又有点像菜单题，搞了一整天了，逆向看了很久，一步步跟着动态调也调了很久。

### 攻击思路
1. 控制好生命值，保证能够撑住前面boss的攻击，后面的攻击就稍微比较弱了，布置好堆风水把tcache对应项填满。
2. boss换成flower的时候会把原来的boss保存到用户临时申请的指针上，将boss释放进unsorted_bin，用malloc申请0字节，会从刚刚释放的unsorted_bin_chunk切割一个0x20的chunk返回，同时长度为0绕过清空。
3. boss回来后之前申请的chunk->fd也被拷贝到boss的新chunk当中，然后把boss->hp(fd)加载到hp_list当中。
4. 采用侧信道的方式来逐字节泄露hp，写一个循环分支，通过与hp的比较结果产生不同的输出，通过记录特定输出字符串的次数来泄露libc。
5. 利用重置boss->damage的方法修改掉tcache_chunk->bk用以检查double_free的字段（2.31新加的检查），然后就可以进行常规double_free攻击了，修改__free_hook写入/bin/sh字符串和system函数。


## musl

这道也整理到musl里面了。

### 攻击思路
1. 申请size为0时有一个堆溢出，构造堆风水来泄露信息。
2. 和DefCon那一道差不多也是伪造meta，但是开了沙箱没法拿shell，所以栈迁移至堆上的ROP链进行ORW。
3. 比较坑的一点是这个题目用flag的目录来恶心你，告诉你在/home/ctf/flag/路径下，但是flag文件名称有问题，然后我就搞不动了。后面队友帮忙补上，先用open('/home/ctf/flag/', 0x1000, 0)打开这个路径，然后用getdents(3, buf, 0x40)把目录下的文件名读到buf上，最后write打印出来。接下来是常规的ORW了。

## Pokemon

C++写的代码，逆向起来非常恶心，比赛的时候看了好久发现有个溢出，但是没想明白怎么用。

### 攻击思路
1. 先用calloc逐个申请并把对应的tcache填满，避免后续干扰。
2. 构造堆风水，利用溢出将下一个chunk->size域改大造成堆叠。
3. 利用堆叠巧妙申请chunk大小，使得宝可梦的攻击值（chunk->fd）为unsorted_bin的值，就能击败boss。
4. 击败boss后传一个不是皮卡丘的宝可梦，这样就不会去读取随机数，同时利用堆叠，将原先放随机数的位置放成chunk->fd，用以泄露unsorted_bin以及libc基址。
5. 利用堆叠自己设置随机数和initial_chunk指针，把该域设置成__free_hook-8，然后利用打败boss的evole功能，就可以往该指针对应的区域进行任意写，注意还要与随机数异或一下，写入/bin/sh字符串和system函数地址，最后释放该堆块。

## sharing

C++写的属实恶心，本来想一点一点逆向来理解整个程序，后面发现真的不行，函数太多了根本看不完，所以参考其他师傅的WP和自己动手调试来理解程序的逻辑。

也是菜单题一样的逻辑，增删查改，删除是通过move拷贝的时候会释放堆块，同时还有一个后门可以用来任意地址写（每次调用输入一个地址，该字节会-=2）。

### 攻击思路
1. 利用添加时没清空，泄露libc和heap基址。
2. 利用后门使得两个指针指向同一chunk，用edit改掉bk域以绕过检查，然后double_free。
3. 常规tcache_poison攻击。

## unistruct


## warmnote

这道也整理到musl里面了。

### 攻击思路
1. 构造堆风水，利用释放note时没有清空内容来泄露信息，再利用后门泄露secret。
2. 利用edit的溢出覆盖掉offset字节，伪造group, meta, meta_area，利用dequeue函数实现任意地址写。
3. 重新申请以拿到伪造的meta，然后利用堆叠控制meta，从而拿到stdout结构体进行FSOP。
4. 通过FSOP控制程序流，由于开了沙箱，只能栈劫持至ROP链上进行ORW。
