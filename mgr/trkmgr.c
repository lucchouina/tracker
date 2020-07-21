#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include "trkdbg.h"

flgmap_t flgmap[] = {

    { "enable", FLAG_ENABLE, CMD_ENABLE},
    { "poison", FLAG_POISON, CMD_POISON},
    { "validate", FLAG_TRACK, CMD_TRACK},
    { "track", FLAG_VALIDATE, CMD_VALIDATE},
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

appdata_t *getAppConfig(char *name)
{
    int idx;
    
    for(idx=0;idx<nApps;idx++) {
        if(!strcmp(apps[idx].cname, name)) return &apps[idx];
    }
    trkdbg(1,0,0,"Returning %s settings for app '%s'\n", defaultsValid?"DEFAULT":"OFF", name);
    return defaultsValid?&defaultAppSettings:&noMatchAppSettings;
}

static const char *conffile=TRACKER_CONFFILE;
static void readConf(void)
{
FILE *fc=fopen(conffile, "r");
char buf[200];
appdata_t newapps[MAXAPPS], *app=newapps;
uint32_t n=0, line=1;
int error=0;

    if(!fc) {
        trkdbg(0,1,0,"Could not access configuration file %s.\n", conffile);
        trkdbg(0,0,0,"Application tracking is disabled by default.\n");
        trkdbg(0,0,1,"Use CLI to enable tracking (requires application restart).\n");
        return;
    }
    for(app=newapps; fgets(buf, sizeof buf -1, fc) && n<MAXAPPS; line++) {
    
        char *tok=strtok(buf, " \t\n\r");
        char *name;
        
        if(!tok) continue;
        /* parse a single line */
        
        if(tok[0]=='#') continue;
        if(strlen(tok) >= MAXCNAME) {
        
            trkdbg(0,0,0,"Line %d: Application name '%s' too long [max:%d].\n", line, tok, MAXCNAME);
            error++;
            continue;
        }
        name=tok;
        app->flags=app->tag=0;
        while((tok=strtok(NULL, " \t,\r\n")) != NULL) {

            /* parse flags : find '=', get flags name, get on/off toten, get mask value */
            char *equal;
            int32_t mask;
            
            if(!(equal=strchr(tok, '='))) {

                trkdbg(0,0,0,"Line %d: No '=' found in '%s'.\n", line, tok);
                error++;
                continue;
            }
            *equal='\0';
            if((mask=flagMask(tok)) < 0) {
            
                trkdbg(0,0,0,"Line %d: Invalid flag '%s'.\n", line, tok);
                error++;
                continue;
            }
            equal++;
            if(!strcasecmp(equal, "on")) app->flags |= mask;
            else if(strcasecmp(equal, "off")) {
            
                trkdbg(0,0,0,"Line %d: Invalid token should be on|off '%s'.\n", line, equal);
                error++;
                continue;
            }
            else app->flags &= ~mask;
        }
        trkdbg(1,0,0,"ReadConf app='%s'\n", name);
        if(!strcmp(name,"*")) {
            trkdbg(1,0,0,"Setting flags 0x%08x as default.\n", app->flags);
            defaultsValid=1;
            defaultAppSettings.flags=app->flags;
        }
        else {
            
            trkdbg(1,0,0,"Setting flags 0x%08x.\n", app->flags);
            strncpy(app->cname, name, MAXCNAME);
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
}

// we make our best effort to remove the UNIX domain socket file
// else the bind() operation will fail for other users
//
static void intHandler(int status)
{
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
    fprintf(stderr, "usage : trkmgr [-d [-d [ ...]] [ -c <confFile>]\n");
    fprintf(stderr, "        -d incremenst debug verbosity\n");
    fprintf(stderr, "        Default <confFile> is %s\n", TRACKER_CONFFILE);
}

int main(int argc, char **argv)
{
int c;
        
    setSig();
    setupClientSocket();
    setupCliSocket();

    // parse command line arguments
    while ((c = getopt(argc, argv, "dc:")) != EOF) {
        switch (c) {
            case 'd':
                dbgsetlvl(dbggetlvl()+1);
            break;
            case 'c':
                conffile=optarg;
            break;
            default :  case '?':
                usage();
        }
    }   
    
    readConf();
    
    if(!dbggetlvl()) {
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

                trkdbg(0,1,1,"Select failed");
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
