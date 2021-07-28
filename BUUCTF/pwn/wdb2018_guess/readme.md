64位下栈溢出，开了canary和NX保护机制。glibc版本2.23，尽管开了canary保护但是这个实现机制存在问题。

stack smashing攻击：canary被覆盖后会调用```_stack_chk_fail```打印提示信息，是以一个格式化字符串的形式打印的，其中第一个参数%s原先是调用argv[0]也就是可执行文件的名称。
如果能覆盖这个指针就能打印出信息来。

攻击步骤：
1. 把argv[0]覆盖成puts函数got表，泄露libc基址。
2. 把argv[0]覆盖成libc库中的```__environ```变量，泄露栈地址。
3. 把argv[0]覆盖成栈上保存flag的地址，泄露flag。
