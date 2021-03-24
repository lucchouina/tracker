/*

    This file contains a simple set of library overloads that will
    work with the memory tracking framework to supply information
    on how much memory is allocated and where as well as execite
    configuration commands from the framework or user.
    
     #include <stdlib.h>

     void *malloc(size_t size);

     void *calloc(size_t nelem, size_t elsize);

     void free(void *ptr);

     void *memalign(size_t alignment, size_t size);

     void *realloc(void *ptr, size_t size);

     void *valloc(size_t size);

     #include <alloca.h>

     void *alloca(size_t size);
     
     - Luc
*/
#define UNW_LOCAL_ONLY
#define FASTFRAMES

#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <stdarg.h>
#include <malloc.h>
#include <sys/socket.h>

#include <unwind.h>

#define __USE_GNU
#include <dlfcn.h>

#include "trkdbg.h"
#include "trklist.h"

// we link with the preload lib but we can't use it
int ismgr=1;

/* some of the config variables we use */
extern uint32_t enable, tracking, validate, poison, alloctag;
static uint32_t pagesize, curalloc=0, untracked=0, initted=0, ininit=0;

/* lock for mp support */
static pthread_mutex_t trkm=PTHREAD_MUTEX_INITIALIZER;
#define LOCK    (pthread_mutex_lock(&trkm))
#define UNLOCK  (pthread_mutex_unlock(&trkm))

typedef void *type_malloc(size_t size);
typedef void *type_calloc(size_t nelem, size_t elsize);
typedef void  type_free(void *ptr);
typedef void *type_memalign(size_t alignment, size_t size);
typedef void *type_realloc(void *ptr, size_t size);
typedef void *type_valloc(size_t size);

/* file descriptors type of calls  for fd tracking */
typedef int type_dup(int oldfd);
typedef int type_dup2(int oldfd, int newfd);
typedef int type_open(const char *pathname, int flags, mode_t mode);
typedef int type_openat(int dirfd, const char *pathname, int flags, ...);
typedef int type_creat(const char *pathname, mode_t mode);
typedef int type_close(int fd);
typedef int type_pipe(int filedes[2]);
typedef int type_socket(int domain, int type, int protocol);
typedef int type_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

typedef int type_fork(void);

#define MAGIC1 0x1badc0de
#define MAGIC2 0x10defee0
#define MAGIC3 0x1feeddad
#define mkbusy(m) (m|=1)
#define mkfree(m) (m&=~1)
#define isbusy(m) (m|1)

#if __SIZEOF_POINTER__ == 4
    typedef uint32_t ptype;
#else
    typedef uint64_t ptype;
#endif

#define MAXFREERS  4

#define MINALLOC    int32_t
#define trkAlign(s) ((s+sizeof(MINALLOC)-1)&~(sizeof(MINALLOC)-1))
#define OFFSET_OFFSET   0
#define OFFSET_SIZE     1
#define OFFSET_MAGIC    2
#define OFFSET_NWORDS   3 // used in buffer alignment

// how to dump core
#define COREDUMP *(int*)0=0
typedef struct trkblk_s trkblk_t;
#define MAXTAGS 255
typedef struct {
    int total;
    LIST_HEAD(xxx, trkblk_s) list;
} alist_t;

static alist_t alist[MAXTAGS];

struct trkblk_s {

    LIST_ENTRY(trkblk_s) list;		// active list linkage
    uint32_t    tag;                    // current tag number
    ptype       callers[MAXCALLERS];
    ptype       freers[MAXFREERS];
    uint32_t    pad;
    /* following 3 fields need to be in that order to match the indexing used
       when tracking is !enabled() (see #defined above) */
    uint32_t    offset;     /* offset to the start of the start of the allocated buffer */
    uint32_t    size;       /* original size of the request for realloc() */
    uint32_t    magic;
};

struct {

    type_malloc     *realMalloc;
    type_realloc    *realRealloc;
    type_calloc     *realCalloc;
    type_free       *realFree;
    type_memalign   *realMemalign;
    type_valloc     *realValloc;
    
    type_dup        *realDup;
    type_dup2       *realDup2;
    type_open       *realOpen;
    type_openat     *realOpenat;
    type_creat      *realCreat;
    type_close      *realClose;
    type_pipe       *realPipe;
    type_socket     *realSocket;
    type_accept     *realAccept;
    
    type_fork       *realFork;

} realFuncs;

/* dump in hex the content of the supplied subber */
static void dump(void *p, int n)
{
#define NC 8
uint32_t *pi=(typeof(pi))p;
int nw=n/sizeof(*pi), i;
    trkdbg(0,0,0, "Dumping %d words @ %p\n", nw, p);
    for(i=0;i<nw;i++,pi++) {
        if(!(i%NC)) trkdbgContinue(0, "\n    %p", pi);
        trkdbgContinue(0, " %08x", *pi);
    }
    trkdbgContinue(0, "\n");
}

static int countFds(int tag);
static void addFds(void *, uint32_t sizeslot, int curpos, int maxpos, int tag);

/* Function called from the client code trkclient.c to send a full report to
   the manager. So as to not have the client app hang in signal handler for too long, we only do 
   part of the job here i.e. put all of te traces into a shared memory segment with an additional 
   word at the start of each traces for linkage and size */
void libSendReport(int cliIdx, int tag)
{
trkblk_t *tp;
uint32_t total=0;
size_t segsize;
int segid;

    trkdbg(1,0,0,"libSendReport : cliIdx %d tag %d\n", cliIdx, tag);
    // grab the lock
    LOCK;
    /* first pass - how many entries at that tag level */
    LIST_FOREACH(tp, &alist[tag].list, list) {
        total++;
    }
    trkdbg(1,0,0,"libSendReport : found %d entries\n", total);
    total += countFds(tag);
    
    if(total) {
    
        /* create a shared memory segment tp contain this data 
           We have 4 additional field to leave space for btree linkage
        */
        segsize=total*RPTSLOTSIZE;
        segsize += sizeof(int);
        trkdbg(1,0,0,"Seg size for report is %u\n", segsize);
        if((segid=shmget(KEYBASE+getpid(), segsize, IPC_CREAT+0666)) < 0)
            trkdbg(0,1,0,"Could not open shared memory segment.\n");
        else {
            char *pslot, *mapaddr;
            trkdbg(1,0,0,"Attaching to segment ID %d\n", segid);
            if((pslot=mapaddr=shmat(segid, 0, 0))==(void*)-1) {
                trkdbg(0,1,0,"Could not attach to shared memory segment [ size=%d pslot=%p  errno : %d].\n"
                        , segsize, segid, errno);
                shmctl(segid, IPC_RMID, 0);
            }
            else {
                unsigned int newtot=0;
                trkdbg(1,0,0,"Mapped segment to %p curalloc is %08x\n", pslot, curalloc);
                ((int*)pslot)[0]=curalloc;
                pslot += sizeof(int);
                /* transfer info */
                LIST_FOREACH(tp, &alist[tag].list, list) {
                    if(newtot>total) break;
                    newtot++;
                    memmove(pslot+RPTHEADERSIZE,  tp->callers, MAXCALLERS*__SIZEOF_POINTER__);
                    trkdbg(1,0,0,"tp->size=%08x\n", tp->size);
                    RPTSIZE(pslot)=tp->size;
                    RPTTYPE(pslot)=RESTYPE_MEMORY;
                    pslot += RPTSLOTSIZE;

                    #ifdef DEBUG                 
                    {
                    int i, *p=(int*)(pslot-RPTSLOTSIZE);
                       trkdbg(2,0,0,"One slot:");
                        for(i=0;i<MAXCALLERS+1;i++){

                            trkdbg(2,0,0,"[%p]", p[i]);

                        }
                        trkdbg(2,0,0,"\n");
                    }
                    #endif                 
                }
                UNLOCK;
                /* add the fd traces */
                addFds(pslot, RPTSLOTSIZE, newtot, total, tag);
                shmdt(mapaddr);
                sendMgr(CMD_REPORT, 1, curalloc);
                return;
            }
            shmctl(segid, IPC_RMID, 0);
        }
    }
    sendMgr(CMD_REPORT, 0, curalloc);
    UNLOCK;
}

/* make the dyn lynker call trkdbginit() right after the load */
static void end_lib(void) __attribute__((destructor(65535)));
static void end_lib(void) {
    enable=0;
}

static __inline__ int enabled(void)
{
    return enable && !ininit;
}

/************************** early init recursivity sheild ***********************/
#define MYBUFSIZE 1024
static char mybuf[MYBUFSIZE];
static int mypos = 0;

static void *mymalloc(size_t size)
{
size_t end;

    /* align to sizeof(int) */
    size=(size+sizeof(int)-1) & ~(sizeof(int)-1);
    end=mypos+size+sizeof(int);
    if(end>=MYBUFSIZE) {        
        trkdbg(0,0,0,"Out of early init buffer space (%d max) need (%d)\n", MYBUFSIZE, end-MYBUFSIZE);
        COREDUMP;
    }
    *(int*)(mybuf+mypos)=MAGIC3;
    mypos+=sizeof(int)+size;
    return mybuf+mypos-size;
}
static void *mycalloc(size_t nelem, size_t elsize)
{
void *ptr=mymalloc(nelem*elsize);

    memset(ptr, 0, nelem*elsize);
    return ptr;
}
static void myfree(void *ptr)
{
    if(*(int*)(((char*)ptr)-sizeof(int)) != MAGIC3) {
        trkdbg(0,0,0,"Early free of invalid pointer\n");
        COREDUMP;
    }
    /* we do nothing else then validate */
}

/********************************************************************************/

/* make the dyn lynker call trkdbginit() right after the load */
static void init_lib(void) __attribute__((constructor));
static void init_lib(void) {
char *dbgvalstr;
int dbgval;
int missing=0;


    if(initted || ininit) {
        return;
    }
    ininit=1;
    /*
        Make a list fo the real symbols.
        fatal is any of the symbols are not resolved.
    */
    if((dbgvalstr=getenv("TRKDEBUG"))) {
        if((dbgval=atoi(dbgvalstr))>=0) dbgsetlvl(dbgval);
        else trkdbg(0,0,0,"Invalid debug level value past in environment [%s]\n", dbgvalstr);
    }
    
    trkdbg(3,0,0,"trkdbginit : start\n");
    if(dlsym(RTLD_NEXT, "si_socket_api_init")) {
        ((void (*)(void)) dlsym(RTLD_NEXT, "si_socket_api_init"))();
    }
    if(!(
        (realFuncs.realMalloc    = (type_malloc*)    dlsym(RTLD_NEXT, "malloc"))
        && ++missing &&
        (realFuncs.realCalloc    = (type_calloc*)    dlsym(RTLD_NEXT, "calloc"))
        && ++missing &&
        (realFuncs.realRealloc   = (type_realloc*)   dlsym(RTLD_NEXT, "realloc"))
        && ++missing &&
        (realFuncs.realFree      = (type_free*)      dlsym(RTLD_NEXT, "free"))
        && ++missing &&
        (realFuncs.realMemalign  = (type_memalign*)  dlsym(RTLD_NEXT, "memalign"))
        && ++missing &&
        (realFuncs.realValloc    = (type_valloc*)    dlsym(RTLD_NEXT, "valloc"))
        && ++missing &&
        (realFuncs.realDup       = (type_dup*)       dlsym(RTLD_NEXT, "dup"))
        && ++missing &&
        (realFuncs.realDup2      = (type_dup2*)      dlsym(RTLD_NEXT, "dup2"))
        && ++missing &&
        (realFuncs.realOpen      = (type_open*)      dlsym(RTLD_NEXT, "open"))
        && ++missing &&
#if 0
        (realFuncs.realOpenat    = (type_openat*)    dlsym(RTLD_NEXT, "openat"))
        && ++missing &&
#endif
        (realFuncs.realCreat     = (type_creat*)     dlsym(RTLD_NEXT, "creat"))
        && ++missing &&
        (realFuncs.realClose     = (type_close*)     dlsym(RTLD_NEXT, "close"))
        && ++missing &&
        (realFuncs.realPipe      = (type_pipe*)      dlsym(RTLD_NEXT, "pipe"))
        && ++missing &&
        (realFuncs.realSocket    = (type_socket*)    dlsym(RTLD_NEXT, "socket"))
        && ++missing &&
        (realFuncs.realAccept    = (type_accept*)    dlsym(RTLD_NEXT, "accept"))
        && ++missing &&
        (realFuncs.realFork      = (type_fork*)    dlsym(RTLD_NEXT, "fork"))

    )) trkdbg(0,0,1,"Could not resolve some of the overloaded functions missing=%d!\n", missing);
    
    trkdbg(3,0,0,"realMalloc=0x%08x\n", realFuncs.realMalloc);
    trkdbg(3,0,0,"realCalloc=0x%08x\n", realFuncs.realCalloc);
    trkdbg(3,0,0,"realRealloc=0x%08x\n", realFuncs.realRealloc);
    trkdbg(3,0,0,"realFree=0x%08x\n", realFuncs.realFree);
    trkdbg(3,0,0,"realMemalign=0x%08x\n", realFuncs.realMemalign);
    trkdbg(3,0,0,"realValloc=0x%08x\n", realFuncs.realValloc);
    trkdbg(3,0,0,"realDup=0x%08x\n", realFuncs.realDup);
    trkdbg(3,0,0,"realOpen=0x%08x\n", realFuncs.realOpen);
    trkdbg(3,0,0,"realCreat=0x%08x\n", realFuncs.realCreat);
    trkdbg(3,0,0,"realClose=0x%08x\n", realFuncs.realClose);
    trkdbg(3,0,0,"realPipe=0x%08x\n", realFuncs.realPipe);
    trkdbg(3,0,0,"realSocket=0x%08x\n", realFuncs.realSocket);
    trkdbg(3,0,0,"realAccept=0x%08x\n", realFuncs.realAccept);
    trkdbg(3,0,0,"realFork=0x%08x\n", realFuncs.realFork);

    // need this for handling valloc()
    pagesize=sysconf(_SC_PAGESIZE);
    trkdbg(3,0,0,"trkdbginit : page size is %d\n", pagesize);
    /*
        Open the connection to the management socket.
        If the manager is not listeing - forget it.
        So - not fatal, continue with '!enable'.
    */
    trkdbg(3,0,0,"trkdbginit : client setup.\n", pagesize);
    if(!clientInit()) enable=0;
    
    // Initialize the lists
    {
        int i;
        for(i=0;i<MAXTAGS;i++)
            LIST_INIT(&alist[i].list);
    }
    trkdbg(3,0,0,"trkdbginit : done enable=%d tracking=%d\n", enable, tracking);
    initted++;
    ininit=0;
    
}

#define JUMPOVER    1  // number of frame to jump over before starting to record a backtrace

#ifdef FASTFRAMES

#if defined(__i386) || defined(__x86_64)
#define PCPOS       1
#define FRAMEPOS    0
#elif defined(__sparc)
#define PCPOS       15
#define FRAMEPOS    14
#else
#error Currently supports only sparc and i386 processor abi
#endif

#ifdef __GNUC__

#ifndef OLD_STYLE
typedef struct ctx_s {
    int max, n;
    void **pc;
} ctx_t;

/* helper function for libgcc's _Unwind_Backtrace() */
static _Unwind_Reason_Code libgcc_helper(struct _Unwind_Context *ctx, void *a)
{
    ctx_t *c=(ctx_t*)a;
    
    if(c->n < c->max) c->pc[c->n++]=(void*)_Unwind_GetIP (ctx);
    if(c->n == c->max) return _URC_END_OF_STACK;
    return _URC_NO_REASON;
}
#endif

/* get a traceback */
static int tp_gettrace(ptype *pc, int max)
{
    int i=0, n;
#ifdef OLD_STYLE
    ptype *frame=(ptype*)__builtin_frame_address(0);
    ptype *base=frame;
    int i1=0;

    trkdbg(1,0,0,"-\n");
    // jump over JUMPOVER frames to get to the actual callers
    while(
        i1<JUMPOVER 
        && frame 
        && frame > (ptype*) 0x1000000
        && (frame - base) < (16*1024*1024)
        && frame[PCPOS]) {
        pc[i1]=frame[PCPOS];
        trkdbg(1,0,0,"pc1[%d] %p at %p next is %p\n"
            , i1
            , frame[PCPOS]
            , &frame[PCPOS]
            , frame[FRAMEPOS]
            );
        frame=(ptype*)frame[FRAMEPOS];
        i1++;
    }
    if(i1<JUMPOVER) return 0;
    
    i=0;
    while(
        i<max 
        && frame 
        && frame > (ptype*)0x1000000
        && (frame - base) < (16*1024*1024)) {
        pc[i1]=frame[PCPOS];
        trkdbg(1,0,0,"pc1[%d] %p at %p next is %p\n"
            , i1
            , frame[PCPOS]
            , &frame[PCPOS]
            , frame[FRAMEPOS]
            );
        pc[i]=frame[PCPOS];
        frame=(ptype*)frame[FRAMEPOS];
        i++;
    }
#else // NEW style
    ctx_t ctx;
    ctx.max=max;
    ctx.n=0;
    ctx.pc=(void**)pc;
    /* use the libgcc_s functions to unwind */
    _Unwind_Backtrace(libgcc_helper, &ctx);
    i=ctx.n;
#endif // OLD_STYLE
    // zap the rest of them
    n=i;
    while(i<max) pc[i++]=0;
    return n;
}
#else
#error This file needs to be compiled with the GNU compiler (re: uses GNU __builtin...)
#endif // GNU

#else

/* slow frame using libunwind */
static int tp_gettrace(ptype *pc, int max)
{
    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip, sp;
    int i1=0, i=0, n;

    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    for(i=0; i<JUMPOVER) unw_step(&cursor);
    for(i=0; i<max; i++) { 
        if(unw_step(&cursor) <= 0) break;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        unw_get_reg(&cursor, UNW_REG_SP, &sp);
        trkdbg(0,0,0,"ip = %lx, sp = %lx\n", (long) ip, (long) sp);
        pc[i]=ip;
    }
    return i;
}

#endif // FASTFRAME
static __inline__ uint32_t chkblock(void *ptr)
{
    uint32_t*p=((uint32_t *)ptr)-OFFSET_MAGIC;
    if((p[OFFSET_MAGIC]!=MAGIC1)  && (p[OFFSET_MAGIC]!=MAGIC2)) {
        trkdbg(0,0,0,"Invalid block error [0x%08x] - aborting!\n", p[OFFSET_MAGIC]);
        COREDUMP;
    }
    return p[OFFSET_MAGIC];
}

/*
    Core allocation function.
    
    - trim up the size to the nearest int32_t
    - check if we've been turned on.
*/
static void *tp_alloc(size_t size, int zeroize)
{
    trkblk_t *tp;
    size_t tpsize;
    uint32_t overhead;
    char *p;
    
    trkdbg(0,0,0,"tp_alloc: size=%d (aligned size %d) zeroize=%d\n", size, trkAlign(size), zeroize);
    size=trkAlign(size);
    if(tracking) overhead=sizeof *tp;
    else overhead=(OFFSET_NWORDS) * sizeof(uint32_t);

    tpsize=overhead+size;
    trkdbg(0,0,0,"Tpsize=%d overhead=%d tracking=%d\n", tpsize, overhead, tracking);
    if(zeroize) p=realFuncs.realCalloc(1, tpsize+sizeof(uint32_t));
    else p=realFuncs.realMalloc(tpsize+sizeof(uint32_t));
    if(p) {
        // figure out where to put tp and our offset
        char *ph=(char*)(((size_t)p+overhead));
        trkdbg(0,0,0,"p=%p ph=%p, delta=%d\n", p, ph, ph-p); 
        curalloc += size;
        *(((int*)(p+tpsize)))=MAGIC1;
        if(tracking) {
        
            tp=((typeof(tp))ph)-1;
            trkdbg(0,0,0,"tp=%p p=%p delta=%d\n", tp, p, (char*)tp-p); 

            // get the back track
            tp_gettrace(tp->callers, MAXCALLERS);
            tp->size=size;
            tp->magic=MAGIC2;
            tp->offset=ph-p;
            tp->tag=alloctag;
            
            /* add this block to the allocation list */
            LOCK;
            LIST_INSERT_HEAD(&alist[tp->tag].list, tp, list);
            alist[tp->tag].total += size;
            trkdbg(0,0,0,"Tracking return %p curalloc=%d, tag=%d\n", tp+1, curalloc, tp->tag);
            dump(p, tpsize+sizeof(uint32_t));
            UNLOCK;
        }
        else {
        
            uint32_t *pw=(uint32_t *)ph-OFFSET_NWORDS;
            pw[OFFSET_MAGIC]=MAGIC1;  // header
            pw[OFFSET_SIZE]=size;
            pw[OFFSET_OFFSET]=ph-(char*)p;
            trkdbg(0,0,0,"Tagged return %p curalloc=%d\n", ph, curalloc);
            dump(p, tpsize+sizeof(uint32_t));
        }
        return ph;
    }
    return 0;
    
}

void *malloc(size_t size)
{
    void *ptr;
    if(ininit) return mymalloc(size);
    else init_lib();
    ptr=tp_alloc(size, 0);
    trkdbg(0,0,0,"malloc - returning %p\n", ptr);
    return ptr;
}

void *calloc(size_t nelem, size_t elsize)
{
    if(ininit) return mycalloc(nelem, elsize);
    else {
        void *ptr;
        init_lib();
        ptr=tp_alloc(nelem*elsize, 1);
        trkdbg(0,0,0,"cmalloc - returning %p\n", ptr);
        return ptr;
    }
}

static void verify(void* vptr)
{
    char *ptr=(void*)vptr;
    uint32_t *pw=(uint32_t*)ptr-OFFSET_NWORDS;
    trkdbg(1,0,0,"Verify %p\n", ptr);
    if(*(int*)(ptr-sizeof(int)) == MAGIC3) {
        trkdbg(0,0,0,"Early free detected %p!\n", ptr);
        return;
    }
    if(pw[OFFSET_MAGIC]==(MAGIC1+1) || pw[OFFSET_MAGIC]==(MAGIC2+1)) {
        trkdbg(0,0,0,"Double free on pointer %p!\n", ptr);
        COREDUMP;
    }
    if(pw[OFFSET_MAGIC] != MAGIC1 && pw[OFFSET_MAGIC] != MAGIC2) {
        trkdbg(0,0,0,"Invalid pointer %p in free!\n", ptr);
    }
    /* check the trailer? */
    else if(validate) {

        if(*((uint32_t*)(ptr+pw[OFFSET_SIZE])) != MAGIC1) {

            trkdbg(0,0,0,"Buffer overflow defected! Aborting...\n");
            COREDUMP;
        }
    }
}            

void free(void *vptr)
{
    char *ptr=(char*)vptr;
    if(!ptr) return; // api should not fail on NULL pointer
    if(ininit) return myfree(vptr);
    else init_lib();
    trkdbg(0,0,0, "free %p\n", vptr);
    {
        uint32_t *pw=((uint32_t*)ptr)-OFFSET_NWORDS;
        void *ppc;
        int nppc=0;

        verify(ptr);
        if(pw[OFFSET_MAGIC] == MAGIC3) {
            myfree(vptr);
            pw[OFFSET_MAGIC] |= 1;
            return;
        }
        else if(pw[OFFSET_MAGIC] == MAGIC2) {

            trkblk_t *tp=((trkblk_t*)ptr)-1;
            LOCK;
            if(validate) {
                if(LIST_NEXT(tp,list)) verify(LIST_NEXT(tp,list)+1);
                if((void*)LIST_PREV(tp,list) != (void*)&alist[tp->tag].list) verify(LIST_PREV(tp,list)+1);
            }
            alist[tp->tag].total -= pw[OFFSET_SIZE];
            LIST_REMOVE(tp,list);
            UNLOCK;
            nppc=tp_gettrace(tp->freers, MAXFREERS)*4;
            ppc=tp->freers;
        }
        else if(pw[OFFSET_MAGIC] == MAGIC1) {
        
            curalloc -= pw[OFFSET_SIZE];
        }
        else {
            /* we do not know how big is this one - can't poison */
            realFuncs.realFree(ptr);
            return;
        }
        pw[OFFSET_MAGIC] |= 1;
        if(poison) {

            uint32_t pad=-1;
            char *pp=ptr, *pend=ptr+pw[OFFSET_SIZE];

            if(!nppc) {
                nppc=4;
                ppc=&pad;
            }
            while(pp<pend) {
                if(pend-pp < nppc) nppc=pend-pp;
                memcpy(pp, ppc, nppc);
                pp+=nppc;
            }

        }
        /* to the actual free */
        trkdbg(0,0,0,"realFree(%p) from %p for (%d) %d\n", ptr-pw[OFFSET_OFFSET], ptr, pw[OFFSET_SIZE], pw[OFFSET_SIZE]+pw[OFFSET_OFFSET]);
        //dump(ptr-pw[OFFSET_OFFSET], pw[OFFSET_SIZE]+pw[OFFSET_OFFSET]+sizeof(uint32_t));
        realFuncs.realFree(ptr-pw[OFFSET_OFFSET]);
    }
}

/*
    for realloc, we always realloc.
    Meanning we reallocate to the new size and copy the content
    into the new buffer. This is why we record the original size
    in the header in the first place.
    
*/
void *realloc(void *ptr, size_t size)
{
    trkdbg(0,0,0,"realloc - %p!\n", ptr);
    {
        if(!ptr) {
            ptr=malloc(size);
            trkdbg(5,0,0,"realloc null ptr - returning %p!\n", ptr);
            return ptr;
        }
        if(size) {
            uint32_t *pw=((uint32_t*)ptr)-OFFSET_NWORDS;
            void *new;
            verify(ptr);
            if((new=tp_alloc(size, 0))) {

                size_t oldsize=pw[OFFSET_SIZE];
                size_t ncopy=oldsize>size?size:oldsize;
                memmove(new, ptr, ncopy);
            }
            trkdbg(5,0,0,"realloc enabled - returning %p!\n", new);
            free(ptr);
            return new;
        }
        free(ptr);
    }
    trkdbg(5,0,0,"realloc NULL\n");
    return 0;
}

void *memalign(size_t alignment, size_t size)
{
    void *p=realFuncs.realMemalign(alignment, size);
    if(p) untracked+=size;
    return p;
}

void *valloc(size_t size)
{
    if(!enable) {
        void *p;
        init_lib();
        p=realFuncs.realValloc(size);
        if(p) untracked += size;
    }
    return memalign(pagesize, size);
}

/* file descriptors handlers */
typedef struct fd_s {

    ptype       opener[MAXOPENERS];
    ptype       closer[MAXCLOSERS];
    int         tag;
    int         inUse;
    
} fd_t;

static fd_t fds[MAXFDS];

static int countFds(int tag)
{
int i, tot=0;

    for(i=0;i<MAXFDS;i++) if(fds[i].inUse && fds[i].tag==tag) tot++;
    return tot;
}

static void addFds(void *pslot, uint32_t sizeslot, int curpos, int maxpos, int tag)
{
int i;
uint32_t max=sizeslot<RPTFDSIZE?sizeslot:RPTFDSIZE;

    for(i=0;i<MAXFDS && curpos<maxpos;i++) {
        if(fds[i].inUse && fds[i].tag==tag) {
            memmove((char*)pslot+RPTHEADERSIZE,  fds[i].opener, max-RPTHEADERSIZE);
            RPTSIZE(pslot)=1;
            RPTTYPE(pslot)=RESTYPE_FILE;
            pslot = (char*)pslot + sizeslot;
            curpos++;
        }
    }
}

__inline__ static int fdIsValid(int fd)
{
    if(fd>=0 && fd<MAXFDS) return 1;
    else return 0;
}

static void newFd(int fd)
{
    if(!enable) return;
    if(fdIsValid(fd)) {
        tp_gettrace(fds[fd].opener, MAXOPENERS);
        if(!fds[fd].inUse) {
            fds[fd].inUse=1;     
            fds[fd].tag=alloctag;  
        }
        else trkdbg(1,0,0,"We lost track of allocation of fd %d! [0x%08x] [0x%08x]\n"
            , fd, fds[fd].opener[0], fds[fd].opener[1]);
    }
}

static int closeFd(int fd)
{
int ret;
    ret=realFuncs.realClose(fd);
    init_lib();
    if(!enable) return ret;
    if(!ret && fdIsValid(fd)) {
        
        tp_gettrace(fds[fd].closer, MAXCLOSERS);
        if(fds[fd].inUse) {
            fds[fd].inUse=0;
        }
        else trkdbg(1,0,0,"We lost track of allocation of fd %d! [0x%08x] [0x%08x]\n"
            , fd, fds[fd].closer[0], fds[fd].closer[1]);
    }
    return ret;
}

int dup(int oldfd)
{
    init_lib();
    return realFuncs.realDup(oldfd);
}

int dup2(int oldfd, int newfd)
{
    init_lib();
    return realFuncs.realDup2(oldfd, newfd);
}

int open(const char *pathname, int flags, ...)
{
va_list ap;
int fd;

    init_lib();
    va_start(ap, flags);
    fd=realFuncs.realOpen(pathname, flags, va_arg(ap, int));
    va_end(ap);
    newFd(fd);

    return fd;
}
#if 0
int openat(int dirfd, const char *pathname, int flags, ...)
{
va_list ap;
int fd;

    init_lib();
    va_start(ap, flags);
    fd=realFuncs.realOpenat(dirfd, pathname, flags, va_arg(ap, int));
    va_end(ap);
    newFd(fd);
    return fd;
}
#endif
int creat(const char *pathname, mode_t mode)
{
int fd;

    init_lib();
    fd=realFuncs.realCreat(pathname, mode);
    newFd(fd);
    return fd;
}

int close(int fd)
{
    
    return closeFd(fd);
}

int pipe(int *filedes)
{
int ret;

    init_lib();
    ret=realFuncs.realPipe(filedes);
    if(!ret) {
        newFd(filedes[0]);
        newFd(filedes[1]);
    }
    return ret;
}

int socket(int domain, int type, int protocol)
{
int fd;

    /* recursion during client init phase */
    if(!ininit) init_lib();
    fd=realFuncs.realSocket(domain, type, protocol);
    newFd(fd);
    return fd;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
int fd;

    init_lib();
    fd=realFuncs.realAccept(sockfd, addr, addrlen);
    newFd(fd);
    return fd;
}

pid_t fork(void)
{
int pid;

    init_lib();
    if((pid=realFuncs.realFork()) == 0) {
    
        /* if that worked, then lets close and re-register with mgr */
        if(enable) clientInit();
    }
    return pid;
}
