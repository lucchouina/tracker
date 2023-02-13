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
#ifdef __linux__
#include <sys/ioctl.h>
#else
#include <sys/filio.h>
#endif
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "trkdbg.h"
#include "trkmgrRl.h"

/*
    This is the CLi portion of the manager. 
    We make some assumpions here. We are not running over a tty so we will not get the 
    window resize signals. We also assume xterm type of terminal and force char mode and
    echo from our side on a telnet line discipline handshake.
*/

#define setfd(fd) if(fd >= 0) { if(fd>maxfd) maxfd=fd; FD_SET(fd, fdset); }
typedef struct cli_s {

    int fd;             // -1 --> ununed entry
    int ffd;            // -1 --> ununed  >=0 cliPrt() output to to this fd instead of one above.
    int iac;            // used to track capability exchange state in telnet
    int waiting;        // Waiting for some result of a previous command ?
    int curval;         // use for set command execution 
    int curcmd;         // use for set command execution 
    int tag;            // use report command execution 
    int subCmd;         // What to do with the client(s) reports 
    char ipStr[50];     // IP string generated at connection time
    void *rl;           // librl handle 
    char *scope[20];    // current scope of commands as set with 'set scope <list>'
        
} cli_t;

extern cli_t cli[10];
#define MAXCLI      (sizeof(cli)/sizeof(cli[0]))
#define MAXSCOPE    (sizeof(cli[0].scope)/sizeof(cli[0].scope[0]))
#define MAXIP       (sizeof(cli[0].ipStr))
int summary=0;
cli_t cli[10];

void cliPrt(int idx, const char *cfmt, ...)
{
va_list ap;
char myfmt[300];
char p[300];
char *f1, *f2, *fmt;
uint32_t i;

    fmt=strdup(cfmt);
    if(!fmt) trkdbg(0,0,1,"mem error on cfmt");
    /* convert \n to \r\n for telnet output*/
    if(cli[idx].ffd<0) {
        for(f1=fmt, f2=myfmt, i=0; *f1 && i<sizeof myfmt; f1++) {
            if(*f1=='\n') *f2++='\r';
            *f2++=*f1;
        }
        *f2='\0';
    }
    else strncpy(myfmt, fmt, sizeof myfmt);
    va_start(ap, cfmt);
    vsnprintf(p, sizeof p-1, myfmt, ap);
    if(cli[idx].ffd>=0) {
        int l=strlen(p);
        if(write(cli[idx].ffd, p, l) < l) {
            trkdbg(0,1,0,"Short write to client %d fd %d ['%s']", idx, cli[idx], p);
        }
    }
    else {
        int l=strlen(p);
        if(write(cli[idx].fd, p, l) < l) {
            trkdbg(0,1,0,"Short write to client %d fd %d ['%s']", idx, cli[idx], p);
        }
    }
    va_end(ap);
    free(fmt);
}

void closeCli(int idx)
{
    trkdbg(1,0,0,"Closing cli connection index %d fd %d\n", idx, cli[idx].fd);
    close(cli[idx].fd);
    cli[idx].fd=-1;
    /* free scope strdup()s */ 
    {
        char **one=cli[idx].scope;
        while(*one) {
        
            free(*one);
            one++;
        }
    }
}

typedef void cmdFunc_t(int idx, int argc, char **argv);

typedef struct clicmd_s {

    const char *name;
    const char *description;
    cmdFunc_t *func;
    int wait;  // do we have to wait for some event to continue or can we
               // display the prompt and accept input immediatly after this command

} clicmd_t;

void cliDecWait(int cidx)
{
    if(cli[cidx].waiting) {
        trkdbg(1,0,0,"cli wait count for client %d is %d\n", cidx, cli[cidx].waiting);
        if(!(--cli[cidx].waiting)) {
            
            if(cli[cidx].ffd>=0) {
            
                trkdbg(1,0,0,"closing report file for client %d fd %d\n", cidx, cli[cidx].ffd);
                close(cli[cidx].ffd);
                cli[cidx].ffd=-1;
                
            }
            rlShowPrompt(cli[cidx].rl, 1);
        }
    }
}

static void cmdQuit(int idx, int argc, char **argv)
{
    closeCli(idx);
}

static void listCb(int idx, int client, char *name)
{
    cliPrt(idx, "%6d   %s\n", clientsPid(client), name);
}

/* List all of the registered application names */
static void cmdList(int idx, int argc, char **argv)
{
    cliPrt(idx, "   Below is the list of registered application.\n");
    cliPrt(idx, "   Any of these names can be added to you local scope with   - set scope <name>\n");
    cliPrt(idx, "   You can add all registered application with to your scope - set scope all\n");
    cliPrt(idx, "   -- Start of list --\n");
    trkmgrClientWalkList(idx, listCb);
    cliPrt(idx, "   -- End of list --\n");
}

static int trkShellToClient(int idx, const char *cmdstr)
{
    char *stdout=NULL;
    int ret;
    cliPrt(idx, "Shell command\n");
    cliPrt(idx, "==============================================\n");
    ret=trkShell(&stdout, NULL, "bash -c '%s' 2>&1", cmdstr);
    if(stdout) {
        int l=strlen(stdout);
        int pos=0;
        while(pos<l) {
            if(stdout[pos]=='\n') stdout[pos]='\0';
            pos++;
        }
        pos=0;
        while(pos<l) {
            cliPrt(idx, "%s\n\r", stdout+pos);
            pos+=strlen(stdout+pos)+1;
        }
        free(stdout);
    }
    cliPrt(idx, "==============================================\n");
    return ret;
}

static void showRules(int idx)
{
}

/* add a program to the list of tracked processes */
static void cmdAdd(int idx, int argc, char **argv)
{
    int pid=-1;
    if(argc>1) {

        char *stdout=NULL;
        pid_t pid=atoi(argv[1]);
        if(pid > 0) {
            char *service=getService(pid);
            char *prog=getCommand(pid);
            if(!prog || !service) {
                cliPrt(idx, "Pid not found\n");
            }
            else if(!getAppConfig(prog, service)) {
            
                cliPrt(idx, "Pid %d - No rules for program %s service %s found - not added\n", pid, prog, service);
                cliPrt(idx, "Please add '%s,%s $flags' to the config file and 'killall -HUP tracker'\n", prog, service);
            }
            else {
                trkShell(NULL, NULL, "tracker add %d %s", pid, service);
            }
            if(prog) free(prog);
            if(service) free(service);
        }

    } else cliPrt(idx, "usage: add <pid>,\n");  
}

static void cmdMatch(int idx, int argc, char **argv)
{
    if(argc>1) {
        if(argc>4) {
            char buf[1024];
            snprintf(buf, sizeof buf, "%s %s %s", argv[1], argv[2], argv[3]);
            buf[sizeof buf-1]='\0';
            processOneLineToApps(idx, buf);
        }
        else cliPrt(idx, "usage: match OR match prog service rules\nType 'help' for examples\n");
    }
    else showRules(idx);
}

/* add a program to the list of tracked processes */
static void cmdAddSource(int idx, int argc, char **argv)
{
    int pid=-1;
    if(argc>1) {

        char *stdout=NULL;
        pid_t pid=atoi(argv[1]);
        if(pid > 0) {
            char *service=getService(pid);
            char *prog=getCommand(pid);
            if(!prog || !service) {
                cliPrt(idx, "Pid not found\n");
            }
            else if(!getAppConfig(prog, service)) {
            
                cliPrt(idx, "Pid %d - No rules for program %s service %s found - not added\n", pid, prog, service);
                cliPrt(idx, "Please add '%s,%s $flags' to the config file and 'killall -HUP tracker'\n", prog, service);
            }
            else {
                trkShell(NULL, NULL, "tracker add %d %s", pid, service);
            }
            if(prog) free(prog);
            if(service) free(service);
        }

    } else cliPrt(idx, "usage: addSource <pid>\n");  
}

/* add a program to the list of tracked processes */
static void cmdRm(int idx, int argc, char **argv)
{
    int pid=-1;
    if(argc>1) {

        char *stdout=NULL;
        pid_t pid=atoi(argv[1]);
        if(pid > 0) {
            char *service=getService(pid);
            char *prog=getCommand(pid);
            if(!prog || !service) {
                cliPrt(idx, "Pid not found\n");
            }
            else {
                trkShell(NULL, NULL, "tracker rm %d %s", pid, service);
            }
            if(prog) free(prog);
            if(service) free(service);
        }

    } else cliPrt(idx, "usage: add program [service]ex: add mgd,\n");  
}

static int onoff2val(int idx, char *valstr)
{
    if(!strcasecmp(valstr, "on")) return 1;
    if(!strcasecmp(valstr, "off")) return 0;
    cliPrt(idx, "Invalid boolean specified '%s' - must be 'on' or 'off'.\n", valstr);
    return -1;
}

static int inList(char *name, int client, char **list)
{
    while(*list) {
        if(!strcmp(*list, name)) return 1;
        // printf("atoi(%s)=%d clientsPid(%d)=%d\n", *list, atoi(*list), client, clientsPid(client));
        if(atoi(*list) == clientsPid(client)) return 1;
        list++;
    }
    return 0;
}

static int inScope(int idx, int client, char *name)
{
    if(!cli[idx].scope[0] || inList(name, client, cli[idx].scope))
        return 1;
    else return 0;
}

static void reportCb(int idx, int client, char *name)
{
    if(inScope(idx, client, name)){
        int ret=trkmgrClientAskReport(client, idx, cli[idx].tag, cli[idx].subCmd );
        cli[idx].waiting++;
        if(ret < 0) cliDecWait(idx);
    }
}

/* follow the scope list and ask for a report */
static void cmdReportHub(int idx, int argc, char **argv, int subCmd)
{
char *fname=0;

    cli[idx].tag=TAGCUR;
    cli[idx].subCmd=subCmd;
    if(argc==2) {
        if(argv[1][0]>='0' && argv[1][0]<='9') cli[idx].tag=atoi(argv[1]);
        else {
            fname=argv[2];
        }
    } else if(argc==3) {
        fname=argv[1];
        cli[idx].tag=atoi(argv[2]);
    } else if(argc>3) {
        cliPrt(idx, "To many arguments.\n");
        return;
    }
    // if we have a file, open it here.
    if(fname) {
    
        if((cli[idx].ffd=open(fname, O_CREAT+O_RDWR+O_TRUNC, 0644)) < 0){
            cliPrt(idx, "Error opening file '%s' : %s\n", fname, strerror(errno));
            return;
        }
        else trkdbg(1,0,0, "Succesffully opened file '%s' for report ourput fd %d\n", fname, cli[idx].ffd);
    }
    trkmgrClientWalkList(idx, reportCb);
}

static void cmdReport(int idx, int argc, char **argv)
{
    cmdReportHub(idx, argc, argv, REPORT_REPORT);
}

static void incCb(int idx, int client, char *name)
{
    if(inScope(idx, client, name)){
        int newtag=trkmgrClientAskPush(client, idx);
        cliPrt(idx, "%-10s : new tag is %d\n", name, newtag);
    }
}

/* follow the scope list and ask for a report */
static void cmdPush(int idx, int argc, char **argv)
{
    trkmgrClientWalkList(idx, incCb);
}

static void decCb(int idx, int client, char *name)
{
    if(inScope(idx, client, name)){
        int newtag=trkmgrClientAskPop(client, idx);
        cliPrt(idx, "%-10s : new tag is %d\n", name, newtag);
    }
}

/* follow the scope list and ask for a report */
static void cmdPop(int idx, int argc, char **argv)
{
    trkmgrClientWalkList(idx, decCb);
}

static void getVarCb(int idx, int client, char *name)
{
int val;

    if(inScope(idx, client, name)){
        val=trkmgrClientGetVar(client, cli[idx].curcmd);
        cliPrt(idx, "    %-10s : %d\n", name, val);
    }
}

static void getAppVar(int idx, const char *varname, int cmd)
{
    cli[idx].curcmd=cmd;
    trkmgrClientWalkList(idx, getVarCb);
}

static void setVarCb(int idx, int client, char *name)
{
int val;

    if(inScope(idx, client, name)) {
        val=trkmgrClientSetVar(client, cli[idx].curcmd, cli[idx].curval);
        cliPrt(idx, "    %-10s : %s\n", name, val>=0?"ok":"Failed");
    }
}

static void setAppVar(int idx, const char *varname, int cmd, int value)
{
    cli[idx].curval=value;
    cli[idx].curcmd=cmd;
    trkmgrClientWalkList(idx, setVarCb);
}

static void cmdSet(int idx, int argc, char **argv)
{
    if(argc<2) {
        cliPrt(idx, "Usage is : set <variable> <value>\n");
        cliPrt(idx, "Possibilities are:\n");
        cliPrt(idx, "     summary on|off\n");
        cliPrt(idx, "        Turn on summary mode for reports.\n");
        cliPrt(idx, "     validate on|off\n");
        cliPrt(idx, "        Turn on validation code in scoped applications.\n");
        cliPrt(idx, "     tracking on|off\n");
        cliPrt(idx, "        Turn on tracking code in scoped applications. That is actual backtrace of each\n");
        cliPrt(idx, "        allocations and free that the application(s) do. (HEAVY LOAD)\n");
        cliPrt(idx, "     poison   on|off\n");
        cliPrt(idx, "        Turn on poisonning code in scoped applications. This involves filling the freed\n");
        cliPrt(idx, "        buffers with invalid and misaligned addresses for easier detection of use-after-free (MEDIUM LOAD)\n");
        cliPrt(idx, "     tag      <int value>\n");
        cliPrt(idx, "        Change the tag value associated with each allocations. Only used when 'tracking' is enabled\n");
        cliPrt(idx, "     debug <debug Level>\n");
        cliPrt(idx, "        Set debug verbosity level to 'debug level'.\n");
        cliPrt(idx, "     scope    <name1>[ <name2> [ name3]]\n");
        cliPrt(idx, "        Set the list of applications to which the following command will apply. The application names\n");
        cliPrt(idx, "        can be selected from the output of the 'list' command. But a name of an application that as yet\n");
        cliPrt(idx, "        to register can also be specified. Special name 'all' matches all registered applications.\n");
        return;
    }
    if(!strcmp(argv[1], "validate")) {
        int val;
        if(argc < 3) getAppVar(idx, "validate", CMD_VALIDATE);
        else if((val=onoff2val(idx, argv[2]))>=0){
            setAppVar(idx, "validate", CMD_VALIDATE, val);
        }
    }
    else if(!strcmp(argv[1], "summary")) {
        int val;
        if((val=onoff2val(idx, argv[2]))>=0){
            summary=val;
        }
    }
    else if(!strcmp(argv[1], "tracking")) {
        int val;
        if(argc < 3) getAppVar(idx, "tracking", CMD_TRACK);
        else if((val=onoff2val(idx, argv[2]))>=0){
            setAppVar(idx, "tracking", CMD_TRACK, val);
        }
    }
    else if(!strcmp(argv[1], "poison")) {
        int val;
        if(argc < 3) getAppVar(idx, "poison", CMD_POISON);
        else if((val=onoff2val(idx, argv[2]))>=0){
            setAppVar(idx, "poison", CMD_POISON, val);
        }
    }
    else if(!strcmp(argv[1], "debug")) {
        int val;
        if(argc < 3) getAppVar(idx, "debug", CMD_DEBUG);
        else if((val=atoi(argv[2]))>=0){
            setAppVar(idx, "debug", CMD_DEBUG, val);
            dbgsetlvl(val);
        }
    }
    else if(!strcmp(argv[1], "tag")) {
        int val;
        if(argc < 3) getAppVar(idx, "tag", CMD_TAG);
        else if((val=atoi(argv[2]))>=0){
            setAppVar(idx, "tag", CMD_TAG, val);
        }
    }
    else if(!strcmp(argv[1], "scope")) {
    
        if(argc<3) {
        
            char **one=cli[idx].scope;
            cliPrt(idx, "Current scope is :\n");
            if(!*one) cliPrt(idx, "All Registered Applications are within scope.\n");
            else {
            
                while(*one) {
                    cliPrt(idx, "     %s\n", *one);
                    one++;
                }
            }
        } else {
    
            uint32_t i;
            int j;

            for(i=0;i<MAXSCOPE-1;i++) {
                if(cli[idx].scope[i]) free(cli[idx].scope[i]);
                cli[idx].scope[i]=0;
            }
            /* walk the list and save it in cli context. 'all' is match everything registered. */
            if(strcasecmp(argv[2], "all")) {
                for(i=0,j=2;i<MAXSCOPE-1 && j<argc;i++,j++) {
                    cli[idx].scope[i]=strdup(argv[j]);
                }
                cli[idx].scope[i]=0;
            }
        }
    }
    else cliPrt(idx, "Invalid command '%s'.\n", argv[1]);
}

static void cmdHelp(int idx, int argc, char **argv);

static void cmdSnap(int idx, int argc, char **argv)
{
    cmdReportHub(idx, argc, argv, REPORT_SNAP);
}

static void cmdSreport(int idx, int argc, char **argv)
{
    cmdReportHub(idx, argc, argv, REPORT_SREPORT);
}

static clicmd_t cmds[]={

    { "help",            "Display the list of available commands.", cmdHelp, 0},                                                    
    { "list",            "List all of the registered application names.", cmdList , 0},                                             
    { "add pid $pid",    "Enable tracing of pid", cmdAdd , 0},                                             
    { "match [rule]",    "Add a match top the original confg  \r\n"
      "                   ex: match imgd * enable,track,validate,poison\r\n"
      "                   match imgd from all services and enable all flags", cmdMatch , 0},                                             
    { "sdebug pid",      "Enable source line in traces for pid", cmdAddSource , 0},                                             
    { "pop",             "Decrement the current allocation tag.", cmdPop, 0},         
    { "push",            "Increment the current allocation tag.", cmdPush, 0},         
    { "snap",            "Take a snapshot of all allocations call stack for later compare.", cmdSnap, 0},         
    { "sreport",         "Show difference in allocation from all unique call stacks.", cmdSreport, 0},         
    { "quit",            "exit the cli altogether",  cmdQuit, 0},                                                                   
    { "report [file] [tag]", "Report allocations\n\r"
      "                  Examples: report 0 -or- report -or- report /tmp/report1 -or- report /tmp/foo 3\n\r"
      "                  Optional 'tag' defaults to current tag.\n\r"
      "                  Optional 'file' defaults to console.", cmdReport, 1},                     
    { "set",    "Set the value of memory tracking variables for the current scope. Usage : set <variable> <value>", cmdSet, 0},                           
};
#define MAXCMD (sizeof(cmds)/sizeof(cmds[0]))

static void cmdHelp(int idx, int argc, char **argv)
{
    uint32_t i;
    cliPrt(idx, "List of possible commands is :\n");
    for(i=0;i<MAXCMD; i++) {
        cliPrt(idx, "%-15s - %s\n", cmds[i].name, cmds[i].description);
    }
}

static clicmd_t *getCmd(char *name)
{
    uint32_t i;
    for(i=0;i<MAXCMD;i++) 
        if(!strcmp(cmds[i].name, name))
            return cmds+i;
    return 0; 
}

/* client to server exchanges */
int cliNewCmd(const char *cmdstr, int idx)
{
int ret=0;
char *argv[10];
uint32_t argc=0;
char *tok, *last;
char *local=strdup(cmdstr);
clicmd_t *cmd;
#define MAXARGS (sizeof(argv)/sizeof(argv[0]))

    tok=strtok_r(local, " \t", &last);
    while(tok && argc<MAXARGS) {
        argv[argc++]=tok;
        trkdbg(1,0,0,"Argv[%d]='%s'\n", argc-1, tok);
        tok=strtok_r(NULL, " \t", &last);
    }
    
    /* return on empty line */
    if(!argc) ret=1;
    else {
        if(!(cmd=getCmd(argv[0]))) {

            trkShellToClient(idx, cmdstr);
            ret=1;
        }
        else {

            trkdbg(1,0,0,"Before execution of cmd '%s'\n", argv[0]);
            (*cmd->func)(idx, argc, argv);
            trkdbg(1,0,0,"After execution of cmd '%s'\n", argv[0]);
            if(!cli[idx].waiting) ret=1;
        }
    }
    free(local);
    return ret;
}

/*
   Get a char. Check for telnet IAC and goble it.
   0: gobled it.
   >0: got a valid char
  -1: connection closed.
*/
#define IAC         255
#define IAC_BREAK   243
int cliGetchar(int idx)
{
    uint8_t c;
    if(read(cli[idx].fd, &c, 1)==1) {
    
        if(cli[idx].iac) {
            cli[idx].iac++;
            // done receiving a triplet?
            if(cli[idx].iac==3) {
                cli[idx].iac=0;
            }
            // done receiving a duplet
            else if(c==IAC || c==IAC_BREAK) {
            
                cli[idx].iac=0;
            }
            return 0;
        
        } else if(c==IAC) {
        
            cli[idx].iac=1;
            return 0;
        }
        return c;
    }
    return -1;
}

void cliPutStr(int idx, const char *s)
{
    int l=strlen(s);
    if(cli[idx].fd >=0 && write(cli[idx].fd, s, l) < l) {
        trkdbg(0,1,0,"Short write to client %d fd %d '%s'", idx, cli[idx].fd, s);
    }
}

static int cliFd=(-1);

#define IACSET(x,a,b,c) x[0] = a; x[1] = b; x[2] = c;
static void cli_telnet_init(int fd)
{
    char buf[3];
    /* Send the telnet negotion to put telnet in binary, no echo, single char mode */
    IACSET(buf, 0xff, 0xfb, 0x01);  /* IAC WILL ECHO */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfb, 0x03);  /* IAC WILL Suppress go ahead */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfb, 0x00);  /* IAC WILL Binary */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfd, 0x00);  /* IAC DO Binary */
    send(fd, (char *)buf, 3, 0);
}

static void newCli(void)
{
struct sockaddr_in addr;
int s;
socklen_t len;

    len = sizeof(addr);
    if ((s=accept(cliFd, (struct sockaddr*)&addr, &len)) == -1)
        trkdbg(0,1,0, "New clent connection failed (accept)");
    else {
    
        /* create a new client entry */
        uint32_t idx;
        for(idx=0;idx<MAXCLI;idx++) {
        
            if(cli[idx].fd<0) break;
            
        }
        if(idx==MAXCLI) {
        
            trkdbg(0,0,0,"Ran out of client entries.... Dropping connection.\n");
            close(s);
        }
        else {
            unsigned long opt = 1;
            
            inet_ntop(AF_INET, &addr.sin_addr, cli[idx].ipStr, MAXIP);
            trkdbg(1,0,0,"New Cli connection from '%s[%d]'\n", cli[idx].ipStr, idx);
            cli[idx].fd=s;
            cli[idx].ffd=-1;
            cli[idx].iac=0;
            ioctl(s, FIONBIO, &opt);
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
            /* send telnet options */
            cli_telnet_init(s);
            /* allocate a input buffer and a rl context to it */
            cli[idx].rl=rl_init(idx);
        }
    }
}


/* call in here with activity on cli handles */
static void handleCli(int idx)
{
    /* we simply call into the rl layer and it will handle the
       new character(s) and call cliNewCmd() when appropriate */
    trkdbg(1,0,0,"Activity on '%s[%d]'\n", cli[idx].ipStr, idx);
    rl_newChar(cli[idx].rl);
}

int cliSetFds(fd_set *fdset, int maxfd)
{
uint32_t idx;

    if(cliFd >= 0) {
        setfd(cliFd);
    }
    for(idx=0; idx<MAXCLI; idx++) {

        if(cli[idx].fd>=0 && !cli[idx].waiting) 
            setfd(cli[idx].fd);

    }
    return maxfd;
}

void cliProcessFds(fd_set *fdset)
{
uint32_t idx;

    if(cliFd >= 0 && FD_ISSET(cliFd, fdset)) {
        newCli();
    }
    for(idx=0; idx<MAXCLI; idx++) {

        if(cli[idx].fd>=0 && FD_ISSET(cli[idx].fd, fdset)) handleCli(idx);

    }
}

void setupCliSocket(void)
{
int sock, on=1;
uint32_t i;
struct sockaddr_in addr;

    if((sock=socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        addr.sin_family=AF_INET;
        addr.sin_addr.s_addr=INADDR_ANY;
        addr.sin_port=htons(CLI_PORT);
        if(bind(sock, (struct sockaddr *) &addr, sizeof addr) >= 0) {
            if(listen(sock,64)) trkdbg(0,1,1, "CLI listen");
            cliFd=sock;
            for(i=0;i<MAXCLI;i++) cli[i].fd=-1;
            return;
        } else trkdbg(0,1,1, "CLI bind");
        close(sock);
    } else trkdbg(0,1,1, "CLI socket");
}

void shutdownCliSocket(void)
{
}
