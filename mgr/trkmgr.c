#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <string.h>

#include "trkdbg.h"

flgmap_t flgmap[] = {

    { "enable", FLAG_ENABLE, CMD_ENABLE},
    { "poison", FLAG_POISON, CMD_POISON},
    { "validate", FLAG_VALIDATE, CMD_VALIDATE},
    { "track", FLAG_TRACK, CMD_TRACK},
};
uint32_t NFLAGS=(sizeof(flgmap)/sizeof(flgmap[0]));
static int flagMask(char *flag)
{
uint32_t i;

    for(i=0; i<NFLAGS; i++) {
        if(!strcasecmp(flgmap[i].flgstr, flag)) 
            return flgmap[i].mask;
    }
    return -1;
}

static void flagsPR(int idx, uint32_t flags)
{
uint32_t i;
char *p="";

    for(i=0; i<NFLAGS; i++) {
        if(flags & flgmap[i].mask) {
            cliPrt(idx, "%s%s=on", p, flgmap[i].flgstr);
            p=",";
        }
    }
}

/*
    This is the TP memory debugging framework manager,
    Check out the wiki 'trkdbg' for an overview of the framework.
*/

static int nApps=0, defaultsValid=0;
static appdata_t apps[100];

#define MAXAPPS  (sizeof(apps)/sizeof(apps[0]))

/* default can be overriden by a '*' entry in the conf file */
static appdata_t defaultAppSettings={"", FLAG_ENABLE+FLAG_POISON+FLAG_VALIDATE+FLAG_TRACK,0};
static appdata_t noMatchAppSettings={"", 0, 0};

appdata_t *getAppConfig(char *prog, char *service)
{
    int idx;
    if(!prog || !prog[0]) prog="*";
    if(!service || !service[0]) service="*";
    for(idx=0;idx<nApps;idx++) {
        int pmatch=0, smatch=0;
        trkdbg(1,0,0,"setting %d, %s:%s\n", idx, apps[idx].prog, apps[idx].service);
        if(!strcmp(apps[idx].prog, "*")) pmatch=1;
        else if(!strcmp(apps[idx].prog, prog)) pmatch=1;
        if(!strcmp(apps[idx].service, "*")) smatch=1;
        else if(!strcmp(apps[idx].service, service)) smatch++;
        if(pmatch && smatch) {
            trkdbg(1,0,0,"Returing setting %d, %s:%s\n", idx, apps[idx].prog, apps[idx].service);
            return &apps[idx];
        }
    }
    trkdbg(1,0,0,"No rules matching %s:%s\n", prog, service);
    return NULL;
}

void addAppConfig(char *prog, char *service, int flags)
{
    if(nApps<MAXAPPS) {
        strncpy(apps[nApps].prog, prog, sizeof apps[nApps].prog-1);
        apps[nApps].flags=flags;
        apps[nApps++].tag=0;
    }
    else trkdbg(0,0,0, "Reached max apps %d", MAXAPPS);
}

static int processOneLine(appdata_t *app, char *buf, int line, int idx)
{
int error=1;
char *tok, *prog, *service;

    while(1) {
        trkdbg(1,0,0, "processLine '%s'\n", buf);
        tok=strtok(buf, " \t\n\r");
        if(!tok) break;

        /* parse a single line */
        
        if(tok[0]=='#') break;
        service=strchr(tok, ',');
        if(!service)  service=tok+strlen(tok); /* "" */
        else *service++=0;
        if(strlen(tok) >= MAXPROG) {
        
            trkdbg(0,0,0,"Line %d: Application name '%s' too long [max:%d].\n", line, tok, MAXPROG);
            if(idx>=0) cliPrt(idx,"Application name '%s' too long [max:%d].\n", tok, MAXPROG);
            break;
        }
        if(strlen(service) >= MAXSERVICE) {
        
            trkdbg(0,0,0,"Line %d: Application name '%s' too long [max:%d].\n", line, service, MAXSERVICE);
            if(idx>=0) cliPrt(idx,"Line %d: Application name '%s' too long [max:%d].\n", service, MAXSERVICE);
            break;
        }
        app->flags=app->tag=0;
        prog=tok;
        while((tok=strtok(NULL, " \t,\r\n")) != NULL) {

            /* parse flags : find '=', get flags name, get on/off toten, get mask value */
            char *equal;
            int32_t mask;
            
            if(!(equal=strchr(tok, '='))) {

                trkdbg(0,0,0,"Line %d: No '=' found in '%s'.\n", line, tok);
                if(idx>=0) cliPrt(idx,"No '=' found in '%s'.\n", tok);
                break;
            }
            *equal='\0';
            if((mask=flagMask(tok)) < 0) {
            
                trkdbg(0,0,0,"Line %d: Invalid flag '%s'.\n", line, tok);
                if(idx>=0) cliPrt(idx,"Invalid flag '%s'.\n", tok);
                break;
            }
            equal++;
            if(!strcasecmp(equal, "on")) app->flags |= mask;
            else if(strcasecmp(equal, "off")) {
            
                trkdbg(0,0,0,"Line %d: Invalid token should be on|off '%s'.\n", line, equal);
                if(idx>=0) cliPrt(idx,"Invalid token should be on|off '%s'.\n", equal);
                break;
            }
            else app->flags &= ~mask;
        }
        trkdbg(1,0,0,"ReadConf prog='%s', service='%s'\n", prog, service);
        trkdbg(1,0,0,"Setting flags 0x%08x\n", app->flags);
        strncpy(app->prog, prog, MAXPROG);
        strncpy(app->service, service, MAXSERVICE);
        error=0;
        break;
    }
    return error;
}

void processOneLineToApps(int idx, char *buf)
{
    if(nApps < MAXAPPS) {
        if(!processOneLine(apps+nApps, buf, 0, idx)) nApps++;
    }
    else {
        cliPrt(idx, "Too many matches defined (max %d)\n", MAXAPPS);
    }
}

void showMatches(int idx)
{
int n;
appdata_t *app=&apps[0];

    for(n=0; n<nApps; n++, app++) {
        cliPrt(idx, "%s,%s ", app->prog, app->service);
        flagsPR(idx, app->flags);
        cliPrt(idx, "\n");
        n++;
    }
}

static const char *conffile=TRACKER_CONFFILE;
static void readConf(void)
{
FILE *fc=fopen(conffile, "r");
char buf[200];
appdata_t newapps[MAXAPPS], *app=newapps;
uint32_t n, line=1;
int error=0;

    trkdbg(0,0,0,"readConf - fc = '%p' file is '%s'\n", fc, conffile);
    if(!fc) {
        trkdbg(0,1,0,"Could not access configuration file %s.\n", conffile);
        trkdbg(0,0,0,"Application tracking is disabled by default.\n");
        trkdbg(0,0,0,"Use CLI to enable tracking (requires application restart).\n");
        return;
    }
    for(n=0; n<MAXAPPS; line++) {
        if(!fgets(buf, sizeof buf -1, fc)) break;
        trkdbg(2,0,0,"readConf - buf = '%s'\n", buf);
        if(!processOneLine(app, buf, line, -1)) {
            app++;
            n++;
        }
    }
    if(error) {
        trkdbg(0,0,0,"%d errors detected, configuration file ignored.\n", error);
    }
    else {
        /* we are good to go. Copy the new config over */
        memcpy(apps, newapps, sizeof(newapps));
        nApps=n;
    }
}

static int redoConf=0;
static void sigHandler(int status)
{
    trkdbg(0,0,0,"Got HUP: re-reading config.\n");
    redoConf=1;
}

static void mgrShutDown(void)
{
    shutdownClientSocket();
    shutdownCliSocket();
    exit(0);
}

// we make our best effort to remove the UNIX domain socket file
// else the bind() operation will fail for other users
//
static int shuttingDown=0;
static void intHandler(int status)
{
    shuttingDown=1;
    mgrShutDown();
}

static void setSig(void)
{
struct sigaction action;

    action.sa_handler=intHandler;
    action.sa_flags=SA_RESETHAND;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGSEGV, &action, NULL);
    sigaction(SIGBUS, &action, NULL);
    sigaction(SIGSYS, &action, NULL);
    sigaction(SIGXFSZ, &action, NULL);
    sigaction(SIGXCPU, &action, NULL);
    sigaction(SIGXFSZ, &action, NULL);
    
    action.sa_handler=sigHandler;
    action.sa_flags=SA_RESTART;
    sigaction(SIGHUP, &action, NULL);
}

static void usage(void)
{
    fprintf(stderr, "usage : trackerd [-d [-d [ ...]] [ -c <confFile>]\n");
    fprintf(stderr, "        -d incremenst debug verbosity\n");
    fprintf(stderr, "        Default <confFile> is %s\n", TRACKER_CONFFILE);
}

int main(int argc, char **argv)
{
int c, nofork=0;
        
    setSig();
    setupClientSocket();
    setupCliSocket();
    trkdbg(0,0,0,"Debug init is done\n");
    // parse command line arguments
    while ((c = getopt(argc, argv, "fdc:")) != EOF) {
        switch (c) {
            case 'd':
                dbgsetlvl(dbggetlvl()+1);
            break;
            case 'c':
                conffile=optarg;
            break;
            case 'f':
                nofork=1;
            break;
            default :  case '?':
                usage();
        }
    }   
    setupDbg(nofork);
    trkdbg(0,0,0,"Going to read config\n");
    readConf();
    
    if(!nofork) {
        int pid;
        if((pid=fork())) {
            if(pid<0) trkdbg(0,1,1,"Fork failed.\n");
            exit(0);
        }
    }
    
    while(1) {
    
    
        fd_set fdset;
        int maxfd=0, n;
        struct timeval tv={ tv_sec: 1 };

        FD_ZERO(&fdset);
        maxfd=clientSetFds(&fdset, maxfd);
        maxfd=cliSetFds(&fdset, maxfd);
        if((n=select(maxfd+1, &fdset, 0, 0, &tv))>0) {

            clientProcessFds(&fdset);
            cliProcessFds(&fdset);
        }
        else if(n<0) {

            if(errno != EINTR) {

                if(!shuttingDown) trkdbg(0,1,1,"Select failed");
            }
            else {
                trkdbg(1,0,0,"Select was interupted.\n");
                if(redoConf) {

                    readConf();
                    redoConf=0;
                }
            }
        }
    }
    return 0;
}
