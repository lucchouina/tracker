/*
    This file contains the client side setup for interactions with the manager.
    The protocol is driven by both a signal and the socket exchanges themselves.
    
    On bringup, an initial exchange is performed right after the connection to
    the server is made. This connection will download the settings that the 
    manager has read from the static configuration file.
    
    Since we cannot create a thread and do not want to change the host application -
    we have to resort to the use of a signal which the manager sends to us when ever 
    he has queued a message for us to handle.
    
    The allocation functions masks and unmasks the signal appropriately.
*/
#include <signal.h>
#include <sys/types.h>
#ifdef __linux__
#include <sys/un.h>
#endif
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>

#include "trkdbg.h"

uint32_t enable=0, tracking=0, validate=0, poison=0, alloctag=0;
static int needDoneTrigger;     // set to one for initial multi command exchange
static int sendReport=0;        // set to one when we have a report request pending
static int sock=-1;
static uint32_t seq=0;
static sigset_t sset;

static int sendCmd(int fd, uint32_t *pseq, int cmd, int aux, int aux2)
{
int ret;

    sigprocmask(SIG_BLOCK, &sset, 0);
    if(sendCmdMore(fd, *pseq, cmd, aux, aux2, 0, 0, 0))
        ret=recvAck(fd, pseq);   
    else ret=-1;
    sigprocmask(SIG_UNBLOCK, &sset, 0);
    return ret;
}

/* send the report to the mgr */
static void report(void)
{
    int tag=sendReport-1;
    sendReport=0;
    if(tag == TAGCUR) tag=alloctag;
    libSendReport(sock, tag);
}

static int clientSet(int aux, int aux2)
{
int ret=-1;

    trkdbg(3,0,0,"[[ ClientSet ]]\n");
    switch(aux) {
        case CMD_POISON:     /* arg: bool on [0|1] */
            trkdbg(3,0,0,"Set POISON from %d to %d\n", poison, aux2);
            ret=poison;
            poison=aux2;
        break;
        case CMD_ENABLE:     /* arg: bool on [0|1] */
            trkdbg(3,0,0,"Set ENABLE from %d to %d\n", enable, aux2);
            ret=enable;
            enable=aux2;
        break;
        case CMD_VALIDATE:   /* arg: bool on [0|1] */
            trkdbg(3,0,0,"Set VALIDATE from %d to %d\n", validate, aux2);
            ret=validate;
            validate=aux2;
        break;
        case CMD_TRACK:      /* arg: bool on [0|1] */
            trkdbg(3,0,0,"Set TRACK from %d to %d\n", tracking, aux2);
            ret=tracking;
            tracking=aux2;
        break;
        case CMD_TAG:     /* arg : <tag value> */
            trkdbg(3,0,0,"Set TAG from %d to %d\n", alloctag, aux2);
            ret=alloctag;
            alloctag=aux2;
        break;
        case CMD_DEBUG:     /* arg : <tag value> */
            dbgsetlvl(aux2);
            trkdbg(3,0,0,"Set DEBUG to %d\n", aux2);
            ret=dbggetlvl();
        break;
        default:
            // invalide command
            trkdbg(3,0,0,"Invalid set variable %d received\n", aux);
            return -1;
    }
    return ret;
}

static int clientGet(int aux)
{

    trkdbg(1,0,0,"[[ ClientGet ]]\n");
    switch(aux) {
        case CMD_POISON:
            trkdbg(1,0,0,"Get POISON %d\n", poison);
            return poison;
        break;
        case CMD_ENABLE:
            trkdbg(1,0,0,"Get ENABLE %d\n", enable);
            return enable;
        break;
        case CMD_VALIDATE:
            trkdbg(1,0,0,"Get VALIDATE %d\n", validate);
            return validate;
        break;
        case CMD_TRACK:
            trkdbg(1,0,0,"Get TRACK %d\n", tracking);
            return tracking;
        break;
        case CMD_TAG:
            trkdbg(1,0,0,"Get TAG %d\n", alloctag);
            return alloctag;
        break;
        default:
            // invalide command
            trkdbg(0,0,0,"Invalid get variable %d received\n", aux);
            return -1;
    }
}

/* change (inc/dec) the current tag. Return new value */
static int changeTag(int inc)
{
    if((alloctag || inc!=-1) && (alloctag!=255 || inc!=1))
        alloctag += inc;
    return alloctag;
}

static int clientRcvCB(int idx, cmd_t *cmd, int more, char *pmore)
{
    trkdbg(1,0,0,"ClientRcvCB : command %d received aux=%d more=%d\n", cmd->cmd, cmd->aux[0], more);
    switch(cmd->cmd) {

        case CMD_SET:     /* arg : <tag value> */
            return clientSet(cmd->aux[0], cmd->aux[1]);
        break;
        case CMD_GET:     /* arg : <tag value> */
            return clientGet(cmd->aux[0]);
        break;
        case CMD_REPORT:     /* args : [tag number | -1 for current tag value] */
            sendReport=1+cmd->aux[0];
            return 1;
        break;
        case CMD_DONE:       /* trailer */
            /* complete initial command sequence received */
            needDoneTrigger=0;
            return 1;
        break;
        case CMD_PUSH:       /* increment tag */
            return changeTag(1);
        break;
        case CMD_POP:       /* decrement tag */
            return changeTag(-1);
        break;
        default:
            // invalide command
            trkdbg(0,0,0,"Invalid command %d received\n", cmd);
            return -1;
        break;
    }
}
static void handleExchange(void)
{
    if(sock<0) return;   
    trkdbg(1,0,0,"handleExchange: waiting for messages.\n");
    while(rcvCmd(sock, clientRcvCB, 0)>=0 && needDoneTrigger){
        trkdbg(1,0,0,"handleExchange: got one more message needDoneTrigger[%d].\n",needDoneTrigger);
    }
}

static int connectToMgr(int firstTime)
{
int len;
struct sockaddr_un addr;

    if(sock>0) return 1;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        trkdbg(0,1,0,"Client AF socket failure\n");
        return 0;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, TRACKER_SOCKPATH);
    len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    {
        struct linger l={.l_onoff=1, .l_linger=1};
        setsockopt(sock, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    }
    if (connect(sock, (struct sockaddr *)&addr, len) == -1) {
        close(sock);
        sock=-1;
        trkdbg(0,1,0,"Client AF connect failure\n");
        return 0;
    }
    needDoneTrigger=firstTime;
    trkdbg(1,0,0,"Sending REGISTER with pid %d and is64 %d\n", getpid(), __SIZEOF_POINTER__==8);
    {
	int flags = fcntl(sock, F_GETFD);
	if (flags != -1)
	    fcntl(sock, F_SETFD, flags | FD_CLOEXEC);
    }    
    sendCmd(sock, &seq, CMD_REGISTER, getpid(), __SIZEOF_POINTER__==8);
    return 1;
}

static pthread_t tid;
static void *talkWithManager(void *data)
{
restart:
    while(rcvCmd(sock, clientRcvCB, 0)>=0){
         if(sendReport) report();
    }
    close(sock);
    sock=-1;
    while(1) {

        sleep(1);
        trkdbg(1,0,0,"Trying to reconnect to server.\n");
        if(connectToMgr(0)) goto restart;
    }
    return 0;
}

void sendMgr(int cmd, int aux, int aux2)
{
    sendCmd(sock, &seq, cmd, aux, aux2);
}

int clientInit(void)
{
    /* get initial config */
    if(sock>=0) {
        close(sock);
        sock=-1;
    }
    if(!connectToMgr(1)) {
    
        trkdbg(0,0,0,"Could not connect to trkmgr - Memory debug disabled.\n");
        trkdbg(0,0,0,"Please start tracker and restart this application.\n");
    }
    else {
        /*  While we hold the main thread, make sure w get all config
            from mgr. */
        handleExchange();
        if(!enable) {
                trkdbg(1,0,0,"Not ENABLED - quitting!\n");
                close(sock);
                sock=-1;
                return 1;
        }
        /* fire up the communication thread */
        if(!pthread_create(&tid, 0, talkWithManager, 0)) return 1;
    }
    return 0;
}
