#include <malloc.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>

static int dbglvl=0;

static void tpdbg(int level, int doerr, int die, const char *fmt, ...)
{
va_list ap;
int docr=0;
char myfmt[1024];
char msg[1024], *p=msg;

    strcpy(myfmt, fmt);
    if(level>dbglvl) return;
    // remove trailing CR
    if(myfmt[strlen(myfmt)-1]=='\n') {
        myfmt[strlen(myfmt)-1]='\0';
        docr=1;
    }
    va_start(ap, fmt);
    p += vsnprintf(p, 1024-(p-msg), myfmt, ap);
    if(doerr) {
        char errbuf[100];
        if(strerror_r(errno, errbuf, sizeof errbuf))
            snprintf(errbuf, sizeof errbuf, "error [%d]", errno);
        p += snprintf(p, 1024-(p-msg), " : %s", errbuf);
    }
    if(docr || doerr) *p++='\n';
    *p='\0';
    write(2, msg, p-msg);
    va_end(ap);
    if(die) exit(1);
}

static void func9(void)
{
char *c;

    void *p=malloc(100);
    fprintf(stderr, "hit a key to deallocate...");
    read(0, &c, 1);
    free(p);
}
static void func7(void)
{
    void *p=malloc(100);
    func9();
    free(p);
}
static void func5(void)
{
    void *p=malloc(100);
    func7();
    free(p);
}
static void func3(void)
{
    void *p=malloc(100);
    func5();
    free(p);
}
static void func1(void)
{
    void *p=malloc(100);
    func3();
    free(p);
}
static void *funca9(void)
{
    void *p=malloc(100);
    return p;
}
static void *funca7(void)
{
 void *p=0;
    funca9();
    return p;
}
static void *funca5(void)
{
void *p=0;
    funca7();
    return(p);
}
static void *funca3(void)
{
void *p=0;
    funca5();
    return(p);
}
static void *funca1(void)
{
void *p=0;
    funca3();
    return(p);
}
static void *funca8(void)
{
void *p=malloc(100);
    return p;
}
static void *funca6(void)
{
void *p=0;
    funca8();
    return p;
}
static void *funca4(void)
{
void *p=0;
    funca6();
    return(p);
}
static void *funca2(void)
{
void *p=0;
    funca4();
    return(p);
}
static void *funca0(void)
{
void *p=0;
    funca2();
    return(p);
}
//===
static void *funcb1(void)
{
void *p=0;
    funca2();
    funca3();
    return(p);
}
static void *funcb0(void)
{
void *p=0;
    funcb1();
    return(p);
}

#include <setjmp.h>
static sigjmp_buf jmpenv;
static int expected=1;

static void sigHandler(int sig)
{
    if(expected)
    {
        expected=1;
        fprintf(stderr,"Got Expected Exception: [%d] long jumping.\n", sig);
        siglongjmp(jmpenv, 0);
    }
    else {
        /* reset the handler */
        signal(sig, SIG_DFL);
        return;
    }
}
static void setSig(void (* handler)(int sig))
{
struct sigaction action;

    action.sa_handler=handler;
    action.sa_flags=SA_RESTART;
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGSYS, &action, NULL);
    sigaction(SIGXFSZ, &action, NULL);
    sigaction(SIGXCPU, &action, NULL);
    sigaction(SIGXFSZ, &action, NULL);
}


static void funcOverrun(void)
{
static const int OVERSIZE=200;
char c;

    char *p=malloc(OVERSIZE);
    memset(p, 0, OVERSIZE);
    fprintf(stderr, "NonAligned - Freeing valid pointer after full size memset!\n");
    if(!sigsetjmp(jmpenv, 1)) {
        free(p);
        fprintf(stderr, "NonAligned - No exception : Good!\n");
    }
    else {
        fprintf(stderr, "NonAligned - Got exception : Not Good!\n");
        exit(1);
    }
    // free an invalid porinter
#if 0
    fprintf(stderr, "NonAligned - Freeing invalid pointer!\n");
    if(!sigsetjmp(jmpenv, 1)) {
        free(p+100);
        fprintf(stderr, "NonAligned - No exception : Not Good!\n");
        exit(1);
    }
    else {
        fprintf(stderr, "NonAligned - Got exception : Good!\n");
        
    }
    p=malloc(OVERSIZE);
    c=*((char*)p+OVERSIZE);
    memset(p, 0, OVERSIZE+1);
    fprintf(stderr, "NonAligned - Creating 1 byte overrun!\n");
    
    if(!sigsetjmp(jmpenv, 1)) {
        free(p);
        fprintf(stderr, "NonAligned - No exception : Not Good!\n");
        exit(1);
    }
    else {
        fprintf(stderr, "NonAligned - Got exception : Good!\n");
        *((char*)p+OVERSIZE)=c;
        free(p);
    }
    fprintf(stderr, "About to test valloc()/memalign() hit <CR>...");
    {char cl; read(0, &cl, 1);}
    p=valloc(OVERSIZE);
    memset(p, 0, OVERSIZE);
    fprintf(stderr, "Aligned - Freeing valid pointer after full size memset!\n");
    if(!sigsetjmp(jmpenv, 1)) {
        free(p);
        fprintf(stderr, "Aligned - No exception : Good!\n");
    }
    else {
        fprintf(stderr, "Aligned - Got exception : Not Good!\n");
        exit(1);
    }
    p=valloc(OVERSIZE);
    c=*((char*)p+OVERSIZE);
    memset(p, 0, OVERSIZE+1);
    if(!sigsetjmp(jmpenv, 1)) {
        free(p);
        fprintf(stderr, "Aligned - No exception : Not Good!\n");
        exit(1);
    }
    else {
        fprintf(stderr, "Aligned - Got exception : Good!\n");
        *((char*)p+OVERSIZE)=c;
        free(p);
    }
#endif
    p=malloc(OVERSIZE);
    fprintf(stderr, "Freeing pointer twice.\n");
    if(!sigsetjmp(jmpenv, 1)) {
        free(p);
        free(p);
        fprintf(stderr, "Aligned - No exception : Not Good!\n");
        exit(1);
    }
    else {
        fprintf(stderr, "Aligned - Got exception : Good!\n");
    }
}
#define CRASH (*(int*)0)=0
static int loadDone=0;
static void *oneLoad(void *data)
{
int l, i;
void *ptrs[100];
int test=*(int*)data;

    do
    {
        for(l=4, i=0; l<=4096; l<<=1, i++) {
        
            switch(test) {
            
                case 1: {
                    ptrs[i]=memalign(l, 100);
                    memset(ptrs[i], 0, 100);
                }
                break;
                case 2: {
                    ptrs[i]=malloc(100);
                    memset(ptrs[i], 0, 100);
                    ptrs[i]=realloc(ptrs[i], 200);
                    memset(ptrs[i], 0, 200);
                    ptrs[i]=realloc(ptrs[i], 101);
                    memset(ptrs[i], 0, 101);
                }
                break;
                case 3: {
                    ptrs[i]=valloc(1000);
                }
                break;
                case 4: {
                    ptrs[i]=malloc(100);
                    memset(ptrs[i], 0, 100);
                    ptrs[i]=realloc(ptrs[i], 200);
                    memset(ptrs[i], 0, 200);
                    ptrs[i]=realloc(ptrs[i], 101);
                    memset(ptrs[i], 0, 101);
                    free(ptrs[i]);
                }
                break;
                default:
                    fprintf(stderr, "Invalid test %d\n", test);
                    CRASH; 
                break;
            }
                
        }
        // free al of those
        switch(test) {

            case 1: case 2: case 3:{
                while(i--) {
                    free(ptrs[i]);
                }
            }
            break;
        }

    } while(!loadDone);
    return 0;
}

pthread_t tid[10];

static void loadTest(int nthread, int sec)
{
int t, test;
    
    for(test=1; test<5; test++) {
        fprintf(stderr, "Load test %d with %d thread(s) for %d seconds.\n", test, nthread, sec);
        for(t=0;t<nthread;t++) {

            if(pthread_create(&tid[t], 0, oneLoad, &test)) {
                fprintf(stderr,"Failed to create thread!\n");
                CRASH;
            }
        }
        sleep(sec);
        loadDone++;
        sleep(1);
        loadDone--;
        fprintf(stderr, "Load test %d done.\n", test);
    }
}

//===
int main(int argc, char **argv)
{
char c;
char *dbgvalstr;
int dbgval;

    if((dbgvalstr=getenv("TPMDEBUG"))) {
        if((dbgval=atoi(dbgvalstr))>=0) dbglvl=dbgval;
        else tpdbg(0,0,0,"Invalid debug level value past in environment [%s]\n", dbgvalstr);
    }
    
    if(argc==2 && !strcmp(argv[1], "fd")) goto fdTest;
    
    fprintf(stderr, "hit a key to allocate in subbranches...");
    read(0, &c, 1);
    func1();
    fprintf(stderr, "hit a key to allocate in 2 separate branches...");
    read(0, &c, 1);
    funca1();
    funca0();
    fprintf(stderr, "hit a key to allocate in 2 joint branches...");
    read(0, &c, 1);
    funcb0();
    fprintf(stderr, "hit a key to continue.\n");
    read(0, &c, 1);
    fprintf(stderr, "Checking that exceptions work (full debug must be enabled!).\n");
    setSig(sigHandler);
    funcOverrun();
    fprintf(stderr, "hit a key to continue.\n");
    read(0, &c, 1);
    setSig(SIG_DFL);
    {
        char *pc;
        fprintf(stderr, "Starting heavy testing. Any exceptions is not good!\n");
        fprintf(stderr, "Realloc to bigger\n");
        pc=malloc(100);
        { int i; for(i=0;i<100;i++) pc[i]=i; }
        pc=realloc(pc,200);
        { int i; for(i=0;i<100;i++) if(pc[i]!=i) { fprintf(stderr,"Invalid data after bigger realloc().\n"); CRASH; }}
        fprintf(stderr, "Realloc to smaller\n");
        pc=malloc(200);
        { int i; for(i=0;i<100;i++) pc[i]=i; }
        pc=realloc(pc,100);
        { int i; for(i=0;i<100;i++) if(pc[i]!=i) { fprintf(stderr,"Invalid data after smaller realloc().\n"); CRASH; }}
        fprintf(stderr, "Starting heavy memalign() test. Any exceptions is not good!\n");
        loadTest(1, 5);
        loadTest(4, 20);
    }
fdTest:
#define FNAME "/tmp/trkdbgfdtest"
    fprintf(stderr, "Starting filed escriptor interactive test.\n");
    fprintf(stderr, "Simple open / close which should work.\n");
    unlink(FNAME);
    {
    int fd=open(FNAME, O_RDWR+O_CREAT, 0444);
    
        if(fd<0) tpdbg(0,1,1,"Failed");
        fprintf(stderr, "Verify that file %s exists and has permissions r--r--r--.\n", FNAME);
        fprintf(stderr, "Verify that the 'report' command on the cli shows that trace.\n");
        fprintf(stderr, "Then hit return\n");
        read(0, &c, 1);
        close(fd);
        fprintf(stderr, "Closed. Verify that the 'report' command on the cli does not show that trace.\n");
        fprintf(stderr, "Then hit return\n");
        read(0, &c, 1);
    }
    return 0;
}
