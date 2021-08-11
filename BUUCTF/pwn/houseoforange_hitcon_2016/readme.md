鼎鼎大名的house_of_orange，64位堆题，保护机制全开，有增查改三项功能，没有删除功能比较特别，另外只保存一个堆块。

# 程序分析
1. 添加功能，最多4次，malloc申请0x20大小堆作为house，由用户指定size用malloc申请name堆，最后calloc申请0x20大小的orange堆，price和color没啥用。相关数据结构：
```C
struct orange{
    int price;
    int color;
} orange;
struct house{
    orange *org;
    char *name;
} house;
```
2. 打印功能，打印出house当中name，price，用来信息泄露。
3. 修改功能，最多3次，指定size然后修改name堆块，此处size超过原先大小会造成堆溢出。

# 攻击思路
1. 由于没有释放功能，所以要利用top_chunk大小不够时的操作，此时绕过一些检查就会把old_top_chunk放入unsorted_bin，再申请new_top_chunk。
2. 有一个unsorted_bin_chunk后，申请一个large_bin_chunk，原来那个chunk会先被整理进large_bin中再被切割返回，bk指向large_bins用来泄露libc_base，bk_nextsize指向自身用来泄露heap_base。
3. unsorted_bin attack，利用堆溢出修改unsorted_bin_chunk->bk=_IO_list_all-0x10，下次分配就会导致_IO_list_all写入unsorted_bin地址，这个地址处于main_arena当中没法控制，
所以溢出时顺便把unsorted_bin->size修改为0x61，申请大小不为0x61时会先把unsorted_bin_chunk整理到small_bins（0x60）当中，刚好是此时_IO_list_all._chain域。
4. 进行unsorted_bin attack的堆同时作为伪造的_IO_FILE结构，两种攻击思路：
    * 一是伪造vtable把它劫持到堆空间上，然后在堆上伪造vtable->_IO_OVERFLOW函数指针为system函数，并把fp->_flag改为b'/bin/sh\x00'。这个能用于2.24以前没检查的情况。
    * 二是将vtable改成该段中的其他jump_table，本题使用_IO_str_jumps（libc没有这个符号可以借助_IO_file_jumps的符号加上偏移），然后把fp->_s._free_buffer这个位置的变量改为system函数，
把fp->_IO_buf_base修改为/bin/sh地址，把vtable改成_IO_str_jumps-8，这样调用vtable->_IO_OVERFLOW函数时实际上是调用_IO_str_jumps->_IO_str_finish。这个能用于2.28之前版本。

当然，利用_IO_FILE进行FSPOP攻击，构造方式多种多样，关键照着源码的检查方式去绕就行。

# 参考链接
这个是raycp师傅整理的关于_IO_FILE_的相关源码以及利用方式，写的非常详细！非常推荐！
[参考博客](https://ray-cp.github.io/archivers/IO_FILE_arbitrary_read_write)
