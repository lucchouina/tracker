#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "trkdbg.h"

/**
    This file inplements source level debug info fetching. namely the source and line number 
    for various addresses for processes.
    
    The key is the PID of the process.
    
    The /proc/$PID/smaps is heavily used to figure out the ELF files and their mapping and offsets.
    
    Lookups can only be done for ELF with an associated ,debug file. Anything without such a file
    will return a lookup failure.
    
    For each ELF we fire up a addr2line instance with which we communicate through a pipe[].
**/

/* one addr2line pipe */
typedef struct addrpipe_s {

    char *filename;
    int rfd;            /* read source:line from this fd */
    int wfd;            /* write the addresses, one per line, to this fd */
    struct addrppipe_s *next;   /* addr2line pipe */
    int ref;            /* ref count (mulitple pid may refer to one addr2line pipe */

} addrpipe_t;

static addrpipe_t *pipes=NULL;

/* unlink a pipe with no refs left */
static void unlinkAddrPipe(addrpipe_t *pfree)
{
    addrpipe_t **last=&pipes, *p=files;
    while(p=files; p; p=p->next) {
        if(p==pfree) {
            *last=p->next;
            free(p);
            return;
        }
        last=&p->next;
    }
}

/* free one pipe with no refs left */
static void removeAddrPipe(addrpipe_t *ap)
{
    if(!--ap->ref) {
        trkdbg(0.0.0, "Tearing down addr2line pipe for '%s' ref is %d\n", ap->filename, ap->ref);
        close(wfd);
        close(rfd);
        unlinkAddrPipe(ap);
    }
    else trkdbg(0.0.0, "Pipie to '%s' ref is %d\n", ap->filename, ap->ref);
}

/* one pid and it's mappings */
typedef struct fmapping_s {

    char *fname;
    size_t  base;
    size_t  offset;
    addrpipe_t *pipe;
    struct fmapping_s *next;
    
} fmapping_t;

static  fmapping_t *files=NULL;

static void removeMaping(fmapping_t *fm)
{
    
}

static void removeFileMapping(fmapping_t *fm)
{
    removeAddrPipe(fp->pipe);
    free(fm->pipe);
    removeMaping(fm);
}

typedef struct pidmaps_s {

    int pid;
    char *prog;
    fmapping_t *first;
    struct pidmaps_s *next;

} pidmaps_t;

/* no multithreading for this. So no locks */
static pidmaps_t *pmaps=NULL;
void removePid(pidmaps_t *pm, pidmaps_t **last)
{
    *last=pm->next;
    {
        fmapping_t *fm;
        for(fm=pm->first; fm; fm=fm->next) {
            removeMapping(fm);
        }
    }
    free(pm);
}

/* delete a pid. Called by main when client socket is closed */
void addrClose(pid_t pid)
{
    pidmaps_t *pm=pmaps, **last=&pmaps;
    
    while (pm) {
    
        if(pm->pid==pid) {
            removePid(pm, last);
            trkDbg(0, "Pid %d removed from address maps");
            return;
        }
        last=&(pm->next);
        pm=pm->next;
    }
    trkDbg(0, "Pid %d not found address maps");
}
    
