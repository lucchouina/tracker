#ifndef __trkdbg_h__
#define __trkdbg_h__
#ifdef __linux__
#include <stdint.h>
#endif
#include <sys/types.h>

/* socket file used for communication between managed client and manager */
#define TRACKER_SOCKPATH "/var/tmp/trkdbg.sock"

/* default configuration file path */
#define TRACKER_CONFFILE "/usr/share/tracker/tracker.conf"

#define MAXCALLERS  10
#define MAXFDS      1024
#define MAXOPENERS  6
#define MAXCLOSERS  4
#define RPTHEADERSIZE ((sizeof(int) * 2))
#define RPTSIZE(p) ((int*)p)[0]
#define RPTTYPE(p) ((int*)p)[1]
/*
  Static version for use on the client size in the preload lib
*/
#define RPTSLOTSIZE                 (RPTHEADERSIZE + (__SIZEOF_POINTER__* (MAXCALLERS)))  // add 2 xtra words for size and type
#define RPTFDSIZE                   (RPTHEADERSIZE + (__SIZEOF_POINTER__* (MAXOPENERS)))  // add 2 xtra words for size and type
#define toEntry(i) ((uint32_t *)(base + (i*RPTSLOTSIZE)))
/* 
   dynamic version used on the manager side - and based on connected client arch 
   it is assumed that there is an array of clients[] strust with a is64 value in the compile context.
*/
#define CLIENT_POINTER_SIZE(idx)    (clients[idx].is64?8:4)
#define CLIENT_RPTSLOTSIZE(idx)     (RPTHEADERSIZE + (CLIENT_POINTER_SIZE(idx) * (MAXCALLERS)))  // add 2 xtra words for size and type
#define CLIENT_RPTFDSIZE(idx)       (RPTHEADERSIZE + (CLIENT_POINTER_SIZE(idx) * (MAXOPENERS)))  // add 2 xtra words for size and type
#define toClientEntry(idx, i) ((uint32_t *)(base + (i*CLIENT_RPTSLOTSIZE(idx))))

#define KEYBASE     12013
#define TAGCUR      100
#define ACK_TIMEOUT 1   // seconds to 
typedef enum {

    RESTYPE_MEMORY,
    RESTYPE_FILE

} resType_t;

void closeCli(int idx);
int  cliNewCmd(const char *cmd, int idx);
int  cliGetchar(int idx);
void cliPutStr(int idx, const char *s);
void rl_shutdown(void *rl);
void *rl_init(int idx);
void rl_newChar(void *rl);

/* Port for CLI clients */
#define CLI_PORT 12013
/*
    Enum of possible command exchanged
*/
enum {

    // server -> client
    CMD_SET,        /* set a variable value */
    CMD_GET,        /* get a variable value */
    CMD_ENABLE,     /* arg: none */
    CMD_VALIDATE,   /* arg: bool on [0|1] */
    CMD_POISON,     /* arg: bool on [0|1] */
    CMD_TRACK,      /* arg: bool on [0|1] */
    CMD_TAG,        /* arg : <tag value> */
    CMD_DEBUG,      /* arg : <debug verbosity level> */
    CMD_REPORT,     /* arg : <tag value> */
    CMD_PUSH,       /* arg : <tag value> */
    CMD_POP,        /* arg : <tag value> */
    CMD_DONE,       /* done with command set */
    
    // client -> server
    CMD_REGISTER,   /* args : pid */
    
    // both . It's an [N]ACK
    CMD_ACK,        /* arg: return value of a GET if any */
    
};
#define CMD_MAGIC_STR "JpMd"


// variety of report commands
#define REPORT_REPORT   0
#define REPORT_SNAP     1
#define REPORT_SREPORT  2

/* struct of the command */
typedef struct cmd_s {

    char        magic[4];   // magic which is filled with *magic
    uint32_t    len;        // total len of the command including magic and len
    uint32_t    seq;        // sequencing
    char        cmd;
    uint32_t    aux[2];
} cmd_t;

/* Application config inside trkmgr */
typedef struct appdata_s {

    char prog[100];
    char service[100];
    uint32_t flags;
    uint32_t tag;
    
} appdata_t;
#define MAXPROG (sizeof(((appdata_t*)0)->prog))
#define MAXSERVICE (sizeof(((appdata_t*)0)->service))

typedef struct cdata_s {

    int fd;
    int pid;                    /* preserve for SIGUSR2 */
    int is64;                   /* 64Bit client (64 bits PC addresses) */
    int total;                  /* used during summary report */
    int needConfig;             /* set when client registers and we need to send config */
    int produceFinalReport;     /* set when client finished report and we need to display it */
    int more;                   /* How much data in the report */
    int reportTo;               /* What cli client wants that report */
    int subCmd;                 /* What to do with the report */
    char *pmore;                /* Report data */
    char *prog;                 /* program name */
    char *service;              /* service name */
    uint32_t seq;               /* for message sequencing */
    appdata_t *adata;           /* tracking config */
    void *dbghdl;               /* for dbg adddr2line lookups */
    char *snap;
    int snapsize;
    
} cdata_t;

extern cdata_t clients[100];

#define FLAG_ENABLE         0x00000001
#define FLAG_POISON         0x00000002
#define FLAG_VALIDATE       0x00000004
#define FLAG_TRACK          0x00000008

typedef struct flgmap_s {

    const char *flgstr;
    int32_t mask;
    int cmd;
    
} flgmap_t;

extern flgmap_t flgmap[];
extern uint32_t NFLAGS;

/* shared functions */
void    setupClientSocket(void);
void    clientProcessFds(fd_set *fdset);
int     clientSetFds(fd_set *fdset, int maxfd);

void    cliProcessFds(fd_set *fdset);
int     cliSetFds(fd_set *fdset, int maxfd);
void    setupCliSocket(void);

void    shutdownCliSocket(void);
void    shutdownClientSocket(void);
void    trkdbg(int level, int doerr, int die, const char *fmt, ...);
void    trkdbgContinue(int level, const char *fmt, ...);
int     clientInit(void);
int     setupSig(void);
void    dbgsetlvl(int level);
int     dbggetlvl(void);
void    setupDbg(int);
void    setupClientDbg(void);
appdata_t *getAppConfig(char *prog, char *service);
void    addAppConfig(char *prog, char *service, int flags);
int     sendCmdMore(int fd, int seq, int cmd, int aux, int aux2, int more, char *pmore, int (*cb)(char **buf));
int     recvAck(int fd, uint32_t *seq);
void    sendMgr(int cmd, int aux, int aux2);
void    trkmgrClientWalkList(int idx, void (*cb)(int idx, int client, char *name));
int     trkmgrClientGetVar(int client, int cmd);
int     trkmgrClientSetVar(int client, int var, int value);
int     rcvCmd(int fd, int (*cb)(int idx, cmd_t *cmd, int more, char *pmore), int idx);
void    libSendReport(int fd, int tag);
int     clientsPid(int idx);
int     trkmgrClientAskReport(int client, int idx, int tag, int subcmd);
int     trkmgrClientAskPop(int client, int idx);
int     trkmgrClientAskPush(int client, int idx);
void    cliPrt(int idx, const char *fmt, ...);
void    cliDecWait(int cidx);
void    rlShowPrompt(void *rl, int reset);
char    *getService(pid_t pid);
char    *getCommand(pid_t pid);
void processOneLineToApps(int idx, char *buf);


void buildShowTree(int cliIdx, int clientIdx, int nentries, void **vector, size_t *total);
int trkShell(char **output, int *err, const char *fmt, ...);
#endif
