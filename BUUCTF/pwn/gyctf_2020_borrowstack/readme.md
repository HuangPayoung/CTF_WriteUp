64位下栈溢出，只能覆盖8字节，可以提前在bss段上布置新栈，然后栈劫持移动到新栈。

踩坑点：

1、劫持后的栈尽量往高地址写，因为后续还要返回main函数进行一次溢出，main函数会把栈往低地址抬，一开始劫持栈写的地址太低，导致后面把got表覆盖了，使得程序崩溃。

2、第二次溢出后想尝试调用system函数然后去执行/bin/sh，但是失败了，网上查看别的师傅也碰到类似的问题，所以第二次溢出就不劫持栈了，直接写one_gadget到返回地址。
