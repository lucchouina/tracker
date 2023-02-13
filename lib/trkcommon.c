#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include "trkdbg.h"

int sys_write(int fd, void *buf, int len)
{
    return syscall(SYS_write, fd, buf, len);
}

int sys_read(int fd, void *buf, int len)
{
    return syscall(SYS_read, fd, buf, len);
}

int sys_select(int nfd, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
    return syscall(SYS_select, nfd, r, w, e, tv);
}

int sys_open(char *name, int mode, int perms)
{
    return syscall(SYS_open, name, mode, perms);
}

static int dbglvl=0, dbgfd=2;

void trkdbg(int level, int doerr, int die, const char *fmt, ...)
{
va_list ap;
int docr=0;
char myfmt[1024];
char msg[1024], *p=msg;
static int pid=-1;

    if(level>dbglvl) return;
    if(pid<0) pid=getpid();
    sprintf(myfmt, "[%d] ", pid);
    strcat(myfmt, fmt);
    // remove trailing CR
    if(myfmt[strlen(myfmt)-1]=='\n') {
        myfmt[strlen(myfmt)-1]='\0';
        docr=1;
    }
    va_start(ap, fmt);
    p += vsnprintf(p, 1024-(p-msg), myfmt, ap);
    if(doerr) {
        char errbuf[100];
        snprintf(errbuf, sizeof errbuf, "error [%d]", errno);
        p += snprintf(p, 1024-(p-msg), " : %s", errbuf);
    }
    if(docr || doerr) *p++='\n';
    *p='\0';
    sys_write(dbgfd, msg, p-msg);
    va_end(ap);
    if(die) exit(1);
}

void trkdbgContinue(int level, const char *fmt, ...)
{
va_list ap;
char msg[1024];

    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg-1, fmt, ap);
    msg[sizeof msg -1]='\0';
    sys_write(dbgfd, msg, strlen(msg));
}

void dbgsetlvl(int level)
{
    trkdbg(0,0,0,"Debug level modified from %d to %d\n", dbglvl, level);
    dbglvl=level;
}
int dbggetlvl(void)
{
    return dbglvl;
}

#define LOGFILE "/var/log/trackerd.log"
void setupDbg(int nofork)
{
    int fd;
    if(nofork) fd=fileno(stderr);
    else fd=open(LOGFILE, O_CREAT+O_APPEND+O_RDWR, 0644);
    if(fd>=0) dbgfd=fd;
    trkdbg(0,0,0, "trk debug started to file '%s' fd %d\n", LOGFILE, dbgfd);
}

void setupClientDbg(void)
{
    int fd, pid=getpid();
    char lfname[100];
    snprintf(lfname, sizeof lfname-1, "/var/log/trackerd.client.log");
    lfname[sizeof lfname-1]='\0';
    if((fd=sys_open(lfname, O_CREAT+O_APPEND+O_RDWR, 0644)) >=0) dbgfd=fd;
}

#define CMDLEN  sizeof(cmd_t)
int recvAck(int fd, uint32_t *seq)
{
cmd_t pkt;
int val=-1, n;
fd_set fdset;
struct timeval tv={ tv_sec: ACK_TIMEOUT };

    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    if((n=sys_select(fd+1, &fdset, 0, 0, &tv))>0) {

        trkdbg(1,0,0,"recvAck for seq %d\n", *seq);
        if(sys_read(fd, &pkt, CMDLEN) != CMDLEN) {
            trkdbg(1,1,0,"Failed pkt read.\n", fd);
        }
        else {

            trkdbg(1,0,0,"Received [cmd=%d] pkt[%d]-[%d] with ack = %d\n", pkt.cmd, pkt.seq, *seq, pkt.aux[0]);
            if(pkt.cmd != CMD_ACK) {
                trkdbg(0,0,0,"Invalid command in ack [%d] -[%d]\n", pkt.cmd, CMD_ACK);
            }
            else {
                if(*seq != pkt.seq) {
                    trkdbg(0,0,0,"out of sequence on pkt receive [%d] -[%d]\n", pkt.seq, *seq);
                }
                else val=pkt.aux[0];
            }
        }
        *seq+=1;
    }
    else {
    
        if(!n) {
            trkdbg(1,1,0,"Timeout waiting for client socket %d\n", fd);
        }
        else {
        
            trkdbg(1,1,0,"Error select'ing from client socket %d\n", fd);
        }
    }
    return val;
}

int sendCmdMore(int fd, int seq, int cmd, int aux, int aux2, int more, char *pmore, int (*cb)(char **buf))
{
cmd_t pkt;
int pos=0;

    trkdbg(1,0,0,"Sending seq %d command %d to fd %d\n", seq, cmd, fd);
    trkdbg(1,0,0,"aux1 %d aux2 %d more %d pmore=0x%08x cb=0x%08x\n", aux, aux2, more, pmore, cb);
    strncpy(pkt.magic, CMD_MAGIC_STR, strlen(CMD_MAGIC_STR));
    pkt.len=CMDLEN+more;
    pkt.cmd=cmd;
    pkt.seq=seq;
    pkt.aux[0]=aux;
    pkt.aux[1]=aux2;
    if(sys_write(fd, &pkt, CMDLEN)==CMDLEN) {
    
        if(pmore) {
            while(more) {

                int nw=sys_write(fd, pmore+pos, more);

                if(nw<0) return 0;
                more -= nw;
                pos += nw;
            }
        }
        else if(more) { // use the callback to get more data
            char *buf;
            int nr;
            while((nr=(*cb)(&buf))) {
                int left=nr, lpos=0;
                while(left) {
                
                    int nw;
                    if((nw=sys_write(fd, buf+lpos, left)) < 0) return 0;
                    left-=nw;
                    lpos+=nw;
                }
            }
        }
        return 1;
    }
    else trkdbg(1,0,0,"Short right on sendcmd?!\n");
    return 0;
}

static void sendAck(int fd, cmd_t *cmd, int val)
{
    sendCmdMore(fd, cmd->seq, CMD_ACK, val, 0, 0, 0, 0);
}

int rcvCmd(int fd, int (*cb)(int idx, cmd_t *cmd, int more, char *pmore), int idx)
{
cmd_t pkt;

    trkdbg(1,0,0,"rcvCmd on fd %d idx %d\n", fd, idx);
    if(sys_read(fd, &pkt, CMDLEN) != CMDLEN) {
        trkdbg(1,1,0,"Failed pkt read fd=%d.\n", fd);
    }
    else {
    
        trkdbg(1,0,0,"rcvCmd got one!\n");
        /* some validation */
        if(strncmp(pkt.magic, CMD_MAGIC_STR, sizeof pkt.magic)) {
        
            trkdbg(0,0,0,"Invalid MAGIC on command [seq:%d]\n", pkt.seq);
        }
        else {
        
            char *pmore=0;
            int more,left,ackval;
            left=more=pkt.len-CMDLEN;

            /* process any xtra data in the command */
            trkdbg(1,0,0,"rcvCmd left=%d\n", left);
            if(left) {
                if((pmore=malloc(left))) { // XXX This is from the serve size only at this time. 
                                           // So calling malloc is fine. should call realMalloc  if client
                    int nr=1, pos=0;
                    while(left && (nr=sys_read(fd, pmore+pos, left))>0) {
                        left-=nr;
                        pos+=nr;
                    }
                    if(nr<=0) {

                        trkdbg(0,1,0,"Error on xtra payload read.\n");
                        free(pmore);
                        return -1;
                    }
                }
                else {
                   /* do our best to read and drop the rest of the command */
                    int nr=1, pos=0;
                    trkdbg(0,0,0,"Out of memory on xtra payload buffer allocation for %d bytes\n", left);
                    while(left && (nr=sys_read(fd, pmore+pos, left))>0) {
                        left-=nr;
                        pos+=nr;
                    }
                    return -1;
                }
            }
            /* we've got everything */
            /* callee gets to free the pmore allocation */
            ackval=(*cb)(idx, &pkt, more, pmore);
            
            /* send a [N]ACK to sender */
            sendAck(fd, &pkt, ackval);
            if(pmore) free(pmore);
            trkdbg(1,0,0,"rcvCmd done and sent ackval %d!\n", ackval);
            return ackval;
        }
    }
    trkdbg(1,0,0,"rcvCmd done and error occurred!\n");
    return -1;
}


#define INC 80
int trkShell(char **output, int *err, const char *fmt, ...)
{
    va_list ap;
    FILE *file;
    char buf[1000];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf-1, fmt, ap);
    buf[sizeof buf-1]='\0';

    if(output) {
        int n, status;
        int bsize=INC, pos=0;
        char *p;
        trkdbg(1, 0, 0, "ShellCmdCommon '%s'\n", buf);
        if(!(file=popen(buf, "re"))) {
            trkdbg(0, 1, 0, "popen '%s' failed\n", buf);
            return 0;
        }
        p=malloc(INC);
        while((n=fread(p+pos, 1, bsize-pos, file)) > 0) {
            if(pos+n>=bsize) {
                p=realloc(p, bsize+INC);
                bsize+=INC;
            }
            pos+=n;
        }
        if((status=pclose(file))>=0) {
            trkdbg(1, 0, 0, "Pclose status is 0x%08x\n", status);
            if(WIFEXITED(status)) {
                if(!WEXITSTATUS(status)) {
                    trkdbg(1, 0, 0, "Normal exit 0 from '%s'\n", buf);
                    *output=p;
                    (*output)[pos]='\0';
                    return 1;
                }
                else trkdbg(0, 0, 0, "'%s' - exiting with %d\n", buf, WEXITSTATUS(status));
            }
            else trkdbg(0, 0, 0, "pclose '%s' - status ix 0x%08x\n", buf, status);
            if(err) *err=WEXITSTATUS(status);
        }
        free(p);
        return 0;
    }
    else {
        trkdbg(1, 0, 0, "system command '%s'\n", buf);
        return ! system(buf);
    }
}

