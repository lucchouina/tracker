#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/wait.h>

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
    pid_t pid;
    int rfd;            /* read source:line from this fd */
    int wfd;            /* write the addresses, one per line, to this fd */
    struct addrpipe_s *next;   /* addr2line pipe */
    int ref;            /* ref count (mulitple pid may refer to one addr2line pipe */

} addrpipe_t;

static addrpipe_t *pipes=NULL;

/* unlink a pipe with no refs left */
static void unlinkAddrPipe(addrpipe_t *pfree)
{
    addrpipe_t **last=&pipes, *p;
    for(p=pipes; p; p=p->next) {
        if(p==pfree) {
            *last=p->next;
            free(p->filename);
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
        trkdbg(1,0,0, "Tearing down addr2line pipe for '%s' ref is %d\n", ap->filename, ap->ref);
        close(ap->wfd);
        close(ap->rfd);
        if(ap->pid>0) waitpid(ap->pid, NULL, 0);
        unlinkAddrPipe(ap);        
    }
    else trkdbg(1,0,0, "Pipe to '%s' ref is %d\n", ap->filename, ap->ref);
}

static addrpipe_t *addAddrPipe(char * const name)
{
    addrpipe_t **last=&pipes, *p;
    int fds1[2], fds2[2];
    struct stat stats;

    /* see if we alreadyhave a addr2line for this file */
    for(p=pipes; p; p=p->next) {
        if(!strcmp(p->filename, name)) {
            trkdbg(0,0,0,"Found addrpoipe_t entry for - %s ref = %d\n", name, p->ref+1);
            p->ref++;
            return p;
        }
        last=&p->next;
    }
    
    /* don't have it... time to create it */
    trkdbg(0,0,0,"Creating addrpoipe_t entry for - %s\n", name);
    p=calloc(sizeof *p, 1);
    p->filename=strdup(name);

    /* if the this is not a file don't fire addr2line */
    if(stat(name, &stats)) {
        
        trkdbg(0,0,0,"Creating addrpoipe_t entry for - %s\n", name);
        p->ref=1;
        p->rfd=p->wfd=-1;
        *last=p;
        return p;
    }

    if(pipe(fds1) >= 0) {
        if(pipe(fds2) >= 0) {
            pid_t pid;
            if(!(pid=fork())) {
                char * const argv[10]={ "[addr2line]", "-e", name, "-s", "-p", NULL };
                dup2(fds1[1], 1);
                dup2(fds2[0], 0);
                close(fds1[0]);
                close(fds2[1]);
                trkdbg(0,0,0,"Child execing for file '%s'\n", name);
                execve("/usr/bin/addr2line", argv, NULL);
                trkdbg(0,1,0,"warning - Pid %d execve failed\n", pid);
            }
            else if(pid > 0) {
                trkdbg(0,0,0,"Pid %d child created for '%s'\n", pid, name);
                p->pid=pid;
                p->rfd=fds1[0];
                p->wfd=fds2[1];
                close(fds1[1]);
                close(fds2[0]);
                p->ref=1;
                *last=p;
                return p;
            }
            else {
                trkdbg(0,1,0,"Fork failed\n");
            }
            close(fds2[0]);
            close(fds2[1]);
        }
        else trkdbg(0,1,0,"Pipe fpds2 failed\n");
        close(fds1[0]);
        close(fds1[1]);
    }
    else trkdbg(0,1,0,"Pipe fpds1 failed\n");
    free(p->filename);
    free(p);
    return NULL;
}

/* one pid and it's mappings */
typedef struct fmapping_s {

    char *fname;
    size_t start;
    size_t end;
    off_t offset;
    addrpipe_t *pipe;
    struct fmapping_s *next;
    
} fmapping_t;

typedef struct pidmaps_s {

    int pid;
    char *prog;
    fmapping_t *first;
    struct pidmaps_s *next;
    int ref;

} pidmaps_t;

/* no multithreading for this. So no locks */
static pidmaps_t *pmaps=NULL;

static void removeFileMapping(fmapping_t *fm)
{
    removeAddrPipe(fm->pipe);
    free(fm);
}

static fmapping_t *addFileMapping(char * const fname, size_t start, size_t end, off_t offset)
{
    fmapping_t *fm=calloc(sizeof *fm, 1);

    fm->pipe=addAddrPipe(fname);
    fm->start=start;
    fm->end=end;
    fm->offset=offset;
    fm->fname=strdup(fname);
    return fm;
}

void removeAddrPid(pidmaps_t *pm, pidmaps_t **last)
{
    fmapping_t *fm=pm->first;
    while(fm) {
        fmapping_t *next=fm->next;
        removeFileMapping(fm);
        fm=next;
    }
    free(pm->prog);
    (*last)=pm->next;
    free(pm);
}

/* delete a pid. Called by main when client socket is closed */
void addrClose(void *vpm)
{
    pidmaps_t *pm=pmaps, **last=&pmaps;
    
    while (pm) {
    
        if(pm == vpm) {
            if(!--pm->ref) {
                trkdbg(1,0,0, "Pid %d '%s' removed from address maps\n", pm->pid, pm->prog);
                removeAddrPid(pm, last);
            }
            else trkdbg(1,0,0, "Pid %d pmaps deref to %d\n", pm->pid, pm->ref);
            return;
        }
        last=&(pm->next);
        pm=pm->next;
    }
    trkdbg(1,0,0, "Pid %d not found address maps\n");
}

/* add  PID to the mix - we need to consume the smaps file an dcreate a number of file mapping entrues

Example line from /proc/pid/maps:

        7f0d667b8000-7f0d667d7000 r-xp 00001000 00:14 26                         /lib64/ld-2.30.so

 */
void *addAddrPid(pid_t pid, char *prog)
{
    FILE *f;
    char sfname[40];
    pidmaps_t *pm=NULL;
    
    /* in case, check is pid maps is already with us */
    for(pm=pmaps; pm && pm->pid != pid; pm=pm->next);

    if(!pm) {

        /* ok it's new */
        pm=calloc(sizeof *pm, 1);
        pm->pid=pid;
        pm->prog=strdup(prog);
        pm->next=pmaps;
        pmaps=pm;

        /* scan the list of maps files for one that is executable */
        snprintf(sfname, sizeof sfname -1, "/proc/%d/maps", pid);
        if((f=fopen(sfname, "r"))) {
            char line[2000];
            while(fgets(line, sizeof line -1, f)) {
                char *area, *perms, *soff, *tok, *fname;

                if(!(area=strtok(line, " \n\t"))) break;
                if(!(perms=strtok(NULL, " \n\t"))) break;
                if(!(soff=strtok(NULL, " \n\t"))) break;

                if(!strcmp(perms, "r-xp")) {
                    size_t start, end;
                    off_t offset;
                    fmapping_t *fm;

                    if(!strtok(NULL, " \n\t")) break;
                    if(!strtok(NULL, " \n\t")) break;
                    if(!(fname=strtok(NULL, " \n\t"))) break;

                    /* create a pid mapping for that file */
                    if(sscanf(area, "%lx-%lx", &start, &end) != 2) break;
                    if(sscanf(soff, "%lx", &offset) != 1) break;

                    fm=addFileMapping(fname, start, end, offset);
                    fm->next=pm->first;
                    pm->first=fm;
                }
            }
        }
        else trkdbg(0, 1, 0, "Could not open '%s'\n", sfname);
    }
    pm->ref++;
    return pm;
}

char *addr2line(void *vpm, size_t addr)
{
    pidmaps_t *pm=(pidmaps_t *)vpm;
    fmapping_t *fm;

    trkdbg(2,0,0,"Looking up address %p for '%s'\n", addr, pm->prog);
    for(fm=pm->first; fm; fm=fm->next) {
    
        trkdbg(2,0,0,"%p <= %p <= %p (%s)\n", fm->start, addr, fm->end, fm->fname);
        if(fm->start <= addr && fm->end >= addr) {
        
            if(fm->pipe->wfd>0) {
                char saddr[40];
                char dbginfo[2000];
                snprintf(saddr, sizeof saddr-1, "0x%lx\n", addr-1-fm->start+fm->offset); saddr[sizeof saddr]='\0';
                trkdbg(2,0,0,"Writing %s to pipe start %p offset %p\n", saddr, fm->start, fm->offset);
                if(write(fm->pipe->wfd, saddr, strlen(saddr)) == strlen(saddr)) {
                    int n;
                    if((n=read(fm->pipe->rfd, dbginfo, sizeof dbginfo-2)) > 0) {
                        char *p;
                        dbginfo[n+1]='\0';
                        dbginfo[n]='\n';
                        for(p=dbginfo; *p; p++) 
                            if(*p=='\n') 
                                *p=' ';
                        trkdbg(2,0,0,"Got pipe data '%s'\n", dbginfo);
                        return strdup(dbginfo);
                    }
                    trkdbg(1,1,0,"Failed read  to fd %d\n", fm->pipe->rfd);
                }
                else trkdbg(1,1,0,"Failed address write to fd %d address '%p'\n", fm->pipe->wfd, saddr);
            }
            else return strdup(fm->pipe->filename);
        }
    }
    return strdup("??");
}

#if UT
int main(int argc, char **argv)
{
    void *vpm1=addAddrPid(getpid(), argv[0]);
    void *vpm2=addAddrPid(getpid(), argv[0]);
    void *vpm3;
    dbgsetlvl(1);
    int pid=fork();
    if(pid<=0) {
    
        sleep(3);
        exit(0);
    }
    vpm3=addAddrPid(pid, argv[0]);
    printf("addAddrPid1 (%p) - '%s'\n", addAddrPid, addr2line(vpm1, (uint64_t)addAddrPid));
    printf("addAddrPid1 (%p) - '%s'\n", main, addr2line(vpm1, (uint64_t)main));
    addrClose(vpm1);
    printf("addAddrPid2 (%p) - '%s'\n", addAddrPid, addr2line(vpm2, (uint64_t)addAddrPid));
    printf("addAddrPid2 (%p) - '%s'\n", main, addr2line(vpm2, (uint64_t)main));
    printf("addAddrPid3 (%p) - '%s'\n", addAddrPid, addr2line(vpm3, (uint64_t)addAddrPid));
    printf("addAddrPid3 (%p) - '%s'\n", main, addr2line(vpm3, (uint64_t)main));
    addrClose(vpm2);
    addrClose(vpm3);
    sleep(100);
    return 1;
}
#endif
