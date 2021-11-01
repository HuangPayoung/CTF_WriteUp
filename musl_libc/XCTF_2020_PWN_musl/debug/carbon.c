#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_LIST 0x10
#define MAX_SIZE 0x80

struct item{
    size_t size;
    char* mem;
} ;

struct item* LIST;

int VIEW_LOCK       = 0;
int OVERFLOW_LOCK   = 0;

static inline void a_crash()
{
    __asm__ __volatile__( "hlt" : : : "memory" );
}

int* getint(int* p)
{
    char buf[0x10];

    int ret = read(0, &buf, 0x10);
    if( ret < 0 ) 
        a_crash();
        
    *p = atoi(buf);

    return p;
}

int getstr(char *p, int len)
{
    char buf;
    int ret;
    int i;

    for( i = 0; i < len; ++i )
    {
        ret = read(0, &buf, 1);
        if( ret < 0 )  
            a_crash();

        if( buf == '\n' ) {
            p[i] = '\x00';
            break;
        } else {   
            p[i] = buf;
        }
    }

    return i;
}

int echo(const char* msg)
{
    return write(1, msg, strlen(msg));
}

int check_idx(int idx)
{
    return idx >= 0 && idx < MAX_LIST && LIST[idx].mem \
            && LIST[idx].size >= 0 && LIST[idx].size <= MAX_SIZE;
}

void init()
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    LIST = mmap(0, sizeof(struct item) * MAX_LIST, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if( LIST == (struct item*)-1 ) {
        echo("ERROR: Unable to mmap\n");
        a_crash();
    }

    alarm(30);
}

void prompt()
{
    echo("1) Assign sleeves\n");
    echo("2) Destory sleeves\n");
    echo("3) Transform sleeves\n");
    echo("4) Examine sleeves\n");
    echo("5) Real death\n");
    echo("> ");
}

void alloc()
{
    int size;
    int idx;
    char* p;

    char buf[8];

    for( idx = 0; idx < MAX_LIST && LIST[idx].mem; ++idx );
    if( idx == MAX_LIST ) {
        echo("ERROR: Out of space\n");
        a_crash();
    }

    echo("What is your prefer size? >");
    getint(&size);
    if( size < 0 || size > MAX_SIZE ) {
        echo("ERROR: Invaild size\n");
        a_crash();
    }

    p = malloc(size);
    // if( !p || p == (char*)0xdeadbeef ) {
    if( p == (char*)0xbadbeef ) {
        echo("ERROR: Bad beef\n");
        exit(-1);
    }

    echo("Are you a believer? >");
    getstr(buf, 8);

    echo("Say hello to your new sleeve >");
    if( !strcmp(buf, "Y") && !OVERFLOW_LOCK ) {
        getstr(p, size + 0x50);
        OVERFLOW_LOCK = 1;
    } else {
        getstr(p, size);
    }

    LIST[idx].size = size;
    LIST[idx].mem  = p;

    echo("Done.\n");
}

void delete()
{
    int idx;

    echo("What is your sleeve ID? >");
    getint(&idx);

    if( check_idx(idx) ) {
        free(LIST[idx].mem);
        LIST[idx].size  = 0;
        LIST[idx].mem   = NULL;
    } else {
        echo("ERROR: Invaild ID\n");
        a_crash();
    }

    echo("Done.\n");
}

void edit()
{
    int idx;

    echo("What is your sleeve ID? >");
    getint(&idx);

    if( check_idx(idx) ) {
        getstr(LIST[idx].mem, LIST[idx].size);
    } else {
        echo("ERROR: Invaild ID\n");
        a_crash();
    }

    echo("Done.\n");
}

void view()
{
    int idx;

    if( !VIEW_LOCK ) {

        echo("WARNING! You have only one chance to do this.\n");

        echo("What is your sleeve ID? >");
        getint(&idx);

        if( check_idx(idx) ) {
            echo(LIST[idx].mem);
        } else {
            echo("ERROR: Invaild ID\n");
            a_crash();
        }

        echo("Done.\n");

        VIEW_LOCK = 1;
    } else {
        echo("ERROR: Access denied\n");
        a_crash();
    }
}

int main()
{
    int comm;

    init();

    for(;;)
    {
        prompt();
        getint(&comm);

        switch( comm )
        {
            case 1:
                alloc(); break;
            case 2:
                delete(); break;
            case 3:
                edit(); break;
            case 4:
                view(); break;
            case 5:
                echo("Coward\n"); a_crash();
            default:
                echo("Unknown command\n");
        }
    }
}
