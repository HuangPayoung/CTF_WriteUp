32位下栈溢出，仅能溢出ebp，eip，和额外4字节。

一开始一直没想明白，想利用system的plt表来调用，但是还需要再溢出4字节才能控制到函数参数，在网上看到其他师傅的做法，eip那里用的是call system这条指令。
在call的时候会把返回地址压栈，所以额外的4字节填上参数（sh）的地址即可。
