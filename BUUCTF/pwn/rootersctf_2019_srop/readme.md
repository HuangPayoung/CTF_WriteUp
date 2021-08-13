64位栈溢出，题目也明示了要用SROP完成攻击，第一个Frame栈帧读入/bin/sh字符串，同时完成栈劫持，第二个Frame执行execve系统调用。
