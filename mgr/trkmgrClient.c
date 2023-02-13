#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#ifndef __linux__
#include <procfs.h>
#endif

#include "trkdbg.h"
#include "addr2line.h"

#define setfd(fd) if(fd >= 0) { if(fd>maxfd) maxfd=fd; FD_SET(fd, fdset); }

cdata_t clients[100];
extern int summary;

int clientsPid(int idx) { return clients[idx].pid; }

#define MAXCLIENTS  (sizeof(clients)/sizeof(clients[0]))

static void closeClient(int idx)
{
    trkdbg(1,0,0,"Mgr closing client connection idx %d fd %d\n", idx, clients[idx].fd);
    if(clients[idx].reportTo>=0) cliDecWait(clients[idx].reportTo);
    close(clients[idx].fd);
    clients[idx].fd=-1;
    addrClose(clients[idx].dbghdl);
    free(clients[idx].prog);
}

char *getService(pid_t pid)
{
#define CPATH "/proc/%u/cgroup"
    char cpath[sizeof CPATH+10];
    int fd;
    snprintf(cpath, sizeof cpath-1, CPATH, pid);
    if((fd=open(cpath, O_RDONLY)) >= 0) {
        char content[1000];
        int n;
        if((n=read(fd, content, sizeof content -1)) > 0) {
            char *p=content;
            content[n]='\0';
            trkdbg(5,0,0, "Cgroup file =\n%s\n", content);
            close(fd);
            /* replace all newlines with '\0' */
            while(*p) {
                trkdbg(5,0,0, "*p = '%c'", *p);
                if(*p == ':') {
                    trkdbg(5,0,0, "strcmp with %12.12s", p+1);
                    if(!strncmp(p+1,"name=systemd", 12)) {
                        // found it
                        char *last=p;
                        trkdbg(5,0,0, "Found it");
                        for(last=p; *p && *p != '\n'; p++) {
                            if(*p=='/') last=p+1;
                        }
                        if(*p=='\n') *p='\0';
                        trkdbg(5,0,0, "Returning '%s'", last);
                        return strdup(last);
                    }
                    while(*p != '\n' && *p) p++;  // skip to end of line
                    continue;
                }
                p++;
            }
        }
        else close(fd);
    }
    else trkdbg(0,0,0, "failed to open '%s'", cpath);
    return NULL;
}

char *getCommand(int pid)
{
    char buf[32];
    char prog[MAXPROG];
    char service[MAXPROG];
    char *stdout;;
    if(trkShell(&stdout, NULL, "cat /proc/%ld/comm", (long)pid)) {
        if(stdout) {
            stdout[strlen(stdout)-1]='\0';
            strncpy(prog, stdout, sizeof prog-1);
            free(stdout);
        }
        return strdup(prog);
    }
    return NULL;
}

static void getCmdStr(int idx, int pid)
{
    char *prog=getCommand(pid), *s;
    char service[MAXPROG];
    if(prog) {
        /* now get the service */
        if(s=getService(pid)) {
            strncpy(service, s, sizeof service-1);
        }
        else strcpy(service, "unknown");
    }
    else {
        trkdbg(1,0,0,"Problem reading comm for pid %d!\n", pid);
        closeClient(idx);
        return;
    }
    clients[idx].adata=getAppConfig(prog, service);
    clients[idx].pid=pid;
    clients[idx].prog=prog;
    clients[idx].service=strdup(service);
    trkdbg(1,0,0,"Client '%s:%s' pid %d registered.\n", prog, service, pid);
}

static int getClientVsize(int idx)
{
  char buf[32];

    FILE *f;
    snprintf(buf, sizeof buf, "/proc/%ld/statm", (long)clients[idx].pid);
    if((f=fopen(buf, "r"))) {
        int size;
        while(fscanf(f, "%d", &size) ==1) {
            fclose(f);
            return size;
        } 
        fclose(f);
    }
    return 0;
}

/* Common function for sending from Mgr to client.
*/

static int mgrSendCmd2(int idx, int cmd, int aux1, int aux2)
{
int ackval;

    trkdbg(1,0,0,"Mgr sending cmd %d to client %d pid %d\n", cmd, idx, clients[idx].pid);
    if(sendCmdMore(clients[idx].fd, clients[idx].seq, cmd, aux1, aux2, 0, 0, 0)) {
        if((ackval=recvAck(clients[idx].fd, &clients[idx].seq))>=0) return ackval;
    }
    // tear down this client connection
    closeClient(idx);
    return -1;
}

static int mgrSendCmd1(int idx, int cmd, int aux1)
{
    return mgrSendCmd2(idx, cmd, aux1, 0);
}


/* Cli wants us to walk the list of regsitered apps */
void trkmgrClientWalkList(int idx, void (*cb)(int idx, int client, char *name))
{
    uint32_t i;
    for(i=0;i<MAXCLIENTS;i++) {
        if(clients[i].fd>=0) (*cb)(idx, i, clients[i].prog);
    }
}

/* Cli wants us to display the list of regsitered apps */
int trkmgrClientGetVar(int client, int var)
{
    if(clients[client].fd>=0)
        return mgrSendCmd2(client, CMD_GET, var, 0);
    return -1;
}

/* Cli wants us to display the list of regsitered apps */
int trkmgrClientAskReport(int client, int idx, int tag, int subCmd)
{
    int ret=-1;
    if(clients[client].fd>=0) {
        ret=mgrSendCmd2(client, CMD_REPORT, tag, 0);
        clients[client].reportTo=idx;
        clients[client].subCmd=subCmd;
    }
    return ret;
}

/* Cli wants us to display the list of regsitered apps */
int trkmgrClientAskPush(int client, int idx)
{
    if(clients[client].fd>=0) {
        return mgrSendCmd1(client, CMD_PUSH, 0);
    }
    return -1;
}

/* Cli wants us to display the list of regsitered apps */
int trkmgrClientAskPop(int client, int idx)
{
    if(clients[client].fd>=0) {
        return mgrSendCmd1(client, CMD_POP, 0);
    }
    return -1;
}

/* Cli wants us to display the list of regsitered apps */
int trkmgrClientSetVar(int client, int var, int value)
{
    if(clients[client].fd>=0) {
        return mgrSendCmd2(client, CMD_SET, var, value);
    }
    return -1;
}

/* send a client it's config info through a set of commands */
static void sendConfig(int idx)
{
uint32_t i;

    /* walk through the current settings for this client */
    for(i=0; i<NFLAGS; i++) {
        if(flgmap[i].mask & clients[idx].adata->flags) {
            if(mgrSendCmd2(idx, CMD_SET, flgmap[i].cmd, 1) < 0) return;
        }
        else  {
            if(flgmap[i].mask == FLAG_ENABLE) 
                trkdbg(1,0,0,"Sending DISABLE to transiant client '%s'!\n", clients[idx].prog);
            if(mgrSendCmd2(idx, CMD_SET, flgmap[i].cmd, 0) < 0) return;
        }
    }
    /* let client know we are done */
    mgrSendCmd1(idx, CMD_DONE, 0);
}

static int clientRcvCB(int idx, cmd_t *cmd, int more, char *pmore)
{
    switch(cmd->cmd) {
        case CMD_REGISTER:     /* arg: pid*/
        {
            trkdbg(1,0,0,"Received REGISTER on idx %d pid %d is64 %d.\n", idx, cmd->aux[0], cmd->aux[1]);
            clients[idx].pid=cmd->aux[0];
            clients[idx].is64=cmd->aux[1];
            getCmdStr(idx, clients[idx].pid);
            if(!clients[idx].adata) {
            
                trkdbg(1,0,0,"client %d '%s:%s' has no config, failing registration\n", idx, clients[idx].prog, clients[idx].service);
                closeClient(idx);
                return 0;
            }
            clients[idx].needConfig=1;
            clients[idx].dbghdl=addAddrPid(clients[idx].pid, clients[idx].prog);
            return 1;
        }
        break;
        case CMD_REPORT:       /* getting the report */
            /* We got the full report back */
            trkdbg(1,0,0,"Received REPORT on idx %d pid %d.\n", idx, cmd->aux[0]);
            if(!cmd->aux[0]) {
                if(summary) cliPrt(clients[idx].reportTo, "%-20s [pid %6d] [Proc Size : %6d] [Mallocated - total ->%6d - tagged -> %6d\n"
                        , clients[idx].prog, clients[idx].pid, getClientVsize(idx), cmd->aux[1], 0);
                else cliPrt(clients[idx].reportTo, "Client '%s' pid %d : nothing to report.\n",clients[idx].prog,clients[idx].pid);
                cliDecWait(clients[idx].reportTo);
            }
            else {
                clients[idx].more=more;
                clients[idx].pmore=pmore;
                clients[idx].produceFinalReport=1;
            }
            return 1;
        break;
        default:
            trkdbg(0,0,0,"Invalid command %d\n", cmd->cmd);
            return 0;
        break;
    }
}

static int cmpBackTraces(const void *v1, const void *v2)
{
const uint32_t *t1=*(uint32_t* const*)v1;
const uint32_t *t2=*(uint32_t* const*)v2;
int pc;

    for(pc=2; pc<MAXCALLERS+2; pc++) {
        if(*(t1+pc) < *(t2+pc)) return -1;
        else if(*(t1+pc) > *(t2+pc)) return  1;
    }
    return 0;
}

static void showReport(int idx)
{
int cliIdx=clients[idx].reportTo;
int segid;

    /* get the data from the shared memory segment and process it */
    /* send the output to the asociated cli entry as indicated by the reportTo 
       value in the cli entry clients[idx] */
    
    /*
        We need to :
        
        - find and attch to the shared memory segment
        - use the 4 words of eacg data entry to generate a btree of all entrie
        - Print the btree on the cli out
    */
    // get the shared memory segment
    trkdbg(1,0,0,"showReport : geting shm key %d\n", KEYBASE+clients[idx].pid);
    if((segid=shmget(KEYBASE+clients[idx].pid, 0, O_RDONLY)) < 0)
        trkdbg(0,1,0,"Could not open shared memory segment\n");
    else {
        char *mapaddr;
        trkdbg(1,0,0,"Found shared memory segment key %d [id=%d]\n", KEYBASE+clients[idx].pid, segid);
        if(!(mapaddr=shmat(segid, 0, 0))) {
            trkdbg(0,1,0,"Could mmap shared memory segment\n");
        }
        else {
            /* get the size */
            struct shmid_ds stats;
            trkdbg(1,0,0,"Shared memory segment attached at 0x%08x\n", mapaddr);
            if(!shmctl(segid, IPC_STAT, &stats)) {
                int nentries=stats.shm_segsz/CLIENT_RPTSLOTSIZE(idx);
                trkdbg(1,0,0,"Mapped segment size if %d - %d entries\n", stats.shm_segsz, nentries);
                switch(clients[idx].subCmd) {
                    case REPORT_REPORT:
                    {
                        void **vector;
                        if((vector=malloc(sizeof(void *)*nentries))) {
                            // fill the vector 
                            int i;
                            size_t total;
                            if(!summary) {
                                cliPrt(cliIdx, "==================================================================\n");
                                cliPrt(cliIdx, "Start of report for registered %sbits client '%s' pid %d\n", clients[idx].is64?"64":"32", clients[idx].prog, clients[idx].pid);
                                cliPrt(cliIdx, "==================================================================\n");
                            }
                            for(i=0;i<nentries;i++) vector[i]=mapaddr+sizeof(int)+(i*CLIENT_RPTSLOTSIZE(idx));
                            qsort(vector, nentries, sizeof *vector, cmpBackTraces);
                            buildShowTree(cliIdx, idx, nentries, vector, &total);
                            if(!summary) cliPrt(cliIdx, "==================================================================\n");
                            cliPrt(cliIdx, "%-20s [pid %6d] [Proc Size : %6d] [Mallocated - total ->%6d - tagged -> %10d\n"
                                , clients[idx].prog, clients[idx].pid, getClientVsize(idx), *((int*)mapaddr), total);
                            if(!summary) {
                                cliPrt(cliIdx, "==================================================================\n");
                                cliPrt(cliIdx, "End of report for registered %sbits client '%s' pid %d\n", clients[idx].is64?"64":"32", clients[idx].prog, clients[idx].pid);
                                cliPrt(cliIdx, "==================================================================\n");
                            }
                        }
                        else trkdbg(0,0,0,"Out of memory on orderring vector allocation [%d bytes]\n", sizeof(uint32_t)*nentries);
                    }
                    break;
                    case REPORT_SNAP:{
                        // make copy of the current allocations 
                        if(clients[idx].snap) free(clients[idx].snap);
                        if((clients[idx].snap=malloc(stats.shm_segsz))) {
                            int i;
                            char *p=mapaddr;
                            memmove(clients[idx].snap, mapaddr, stats.shm_segsz);
                            clients[idx].snapsize=stats.shm_segsz;
                            // change the computed sizes to negative values
                            for(i=0, p=clients[idx].snap+sizeof(int); i<nentries; i++, p+=CLIENT_RPTSLOTSIZE(idx)) {
                                *(int*)p = -*(int*)p;
                            }

                        }
                        else cliPrt(cliIdx, "Could not allocate snap buffer of %d bytes\n", stats.shm_segsz);
                    }
                    break;
                    case REPORT_SREPORT:{
                        // show difference in allocation between current report and last snap command.
                        // the approach is to negate the snap sizes and treat the entries of bot the report
                        // and the snap as a single report...
                        if(clients[idx].snap) {
                            void **vector;
                            int nsnap=clients[idx].snapsize/RPTSLOTSIZE, j;
                            if((vector=malloc(sizeof(void *)*(nentries+nsnap)))) {
                                // fill the vector 
                                int i;
                                size_t total;
                                if(!summary) {
                                    cliPrt(cliIdx, "===========================================================\n");
                                    cliPrt(cliIdx, "Start of report for registered %sbits client '%s' pid %d\n", clients[idx].prog,  clients[idx].is64?"64":"32", clients[idx].pid);
                                    cliPrt(cliIdx, "===========================================================\n");
                                }
                                for(i=0;i<nentries;i++) vector[i]=mapaddr+sizeof(int)+(i*CLIENT_RPTSLOTSIZE(idx));
                                for(j=0;j<nsnap;j++) vector[i+j]=clients[idx].snap+sizeof(int)+(j*CLIENT_RPTSLOTSIZE(idx));
                                qsort(vector, nentries+nsnap, sizeof *vector, cmpBackTraces);
                                buildShowTree(cliIdx, idx, nentries+nsnap, vector, &total);
                                if(!summary) cliPrt(cliIdx, "===========================================================\n");
                                cliPrt(cliIdx, "%-20s [pid %6d] [Proc Size : %6d] [Mallocated - total ->%6d - tagged -> %10d\n"
                                    , clients[idx].prog, clients[idx].pid, getClientVsize(idx), *((int*)mapaddr), total);
                                if(!summary) {
                                    cliPrt(cliIdx, "===========================================================\n");
                                    cliPrt(cliIdx, "End of report for registered %sbits client '%s' pid %d\n", clients[idx].prog,  clients[idx].is64?"64":"32", clients[idx].pid);
                                    cliPrt(cliIdx, "===========================================================\n");
                                }
                            }
                            else trkdbg(0,0,0,"Out of memory on orderring vector allocation [%d bytes]\n", sizeof(uint32_t)*nentries);
                        }
                        else cliPrt(cliIdx, "Please execute a snap command first.\n", stats.shm_segsz);
                    }
                    break;
                }
            }
            shmdt(mapaddr);
        }
        shmctl(segid, IPC_RMID, 0);
    }    
    cliDecWait(cliIdx);
}

/* client to server exchanges */
static void handleExchange(int idx)
{
    trkdbg(1,0,0,"handleExchange with client idx %d fd %d\n", idx, clients[idx].fd);
    if(rcvCmd(clients[idx].fd, clientRcvCB, idx) < 0) {
        cliDecWait(clients[idx].reportTo);
        closeClient(idx);
     } else {
        if(clients[idx].needConfig) {

            sendConfig(idx);
            clients[idx].needConfig=0;
        }
        if(clients[idx].produceFinalReport) {

            clients[idx].produceFinalReport=0;
            showReport(idx);
        }   
    }
}

static int serverFd=(-1);

static void newClient(void)
{
int sock;

    if ((sock=accept(serverFd, 0, 0)) == -1)
        trkdbg(0,1,0, "New clent connection failed (accept)");
    else {
    
        /* create a new client entry */
        uint32_t idx;
        trkdbg(1,0,0,"sock is %d\n",sock);
        for(idx=0;idx<MAXCLIENTS;idx++) {
        
            if(clients[idx].fd<0) break;
            
        }
        if(idx==MAXCLIENTS) {
            trkdbg(0,0,0,"Ran out of client entries.... Dropping connection.\n");
            close(sock);
        }
        else {
            trkdbg(1,0,0,"New client on idx %d fd %d\n", idx, sock);
            clients[idx].fd=sock;
        }
    }
}

int clientSetFds(fd_set *fdset, int maxfd)
{
uint32_t idx;

    if(serverFd >= 0) {
        setfd(serverFd);
    }
    for(idx=0; idx<MAXCLIENTS; idx++) {

        if(clients[idx].fd>=0) {
            setfd(clients[idx].fd);
        }

    }
    return maxfd;
}

void clientProcessFds(fd_set *fdset)
{
uint32_t idx;

    if(serverFd >= 0 && FD_ISSET(serverFd, fdset)) {
        newClient();
    }
    for(idx=0; idx<MAXCLIENTS; idx++) {

        if(clients[idx].fd>=0 && FD_ISSET(clients[idx].fd, fdset)) {
            trkdbg(1,0,0,"Setting fd bit %d for idx %d\n", clients[idx].fd, idx);
            handleExchange(idx);
        }
    }
}

void setupClientSocket(void)
{
int s, len;
uint32_t i;
struct sockaddr_un addr;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        trkdbg(0,1,1, "socket");

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, TRACKER_SOCKPATH);
    unlink(addr.sun_path);
    len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    if (bind(s, (struct sockaddr *)&addr, len) == -1) 
        trkdbg(0,1,1, "bind");

    if (listen(s, 5) == -1)
        trkdbg(0,1,1, "listen");
    
    serverFd=s;
    for(i=0;i<MAXCLIENTS;i++) clients[i].fd=-1;
}

void shutdownClientSocket(void)
{
    if(serverFd>=0) {
        close(serverFd);
        unlink(TRACKER_SOCKPATH);
    }
}
