#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <curses.h>
#include <term.h>
#include <termio.h>
#include "trkdbg.h"
#include "trkmgrRl.h"

#define ctrl(c) ((c) & 0x1f)

typedef struct rl_s {

    int maxh;           /* number of buffered commands */
    int maxl;           /* maximum command length */
    const char *prompt;       /* prompt to be used */
    int notty;          /* no controling terminal or missing basic kbd functionality */
    int width;          /* width of the screen we are working from */
    char *buf;
    int curpos;      	/* position of cursor inside the input string */
    int maxpos;      	/* current length of the input string */
    
    int curseq[10];     /* Used while trying to match a special character sequence */
    int seqidx;      	/* where we are in that sequence. */
    
    int cliIdx;
    
    int histoff;
    
    /* history handle */
    void *hist;

} rl_t ;

/* set of global terminal sequences from termcap etc... */
static int termInit=0, xenl;
static const char *bol, *leftN, *rightN, *upN, *downN, *home;
static const char *kup, *kdown, *kleft, *kright, *kdel, *kbksp;
static const char *bip, *kwb, *cod, *kwf, *fw, *bw;
static void rl_resetState(rl_t *rl);

static const char *mygetstr(const char *cname)
{
    char name[strlen(cname)+1];
    strcpy(name, cname);
    return tigetstr(name);
}
static int mygetflag(const char *cname)
{
    char name[strlen(cname)+1];
    strcpy(name, cname);
    return tigetflag(name);
}

static char *mytparm(const char *cstr, int value)
{
    char str[strlen(cstr)+1];
    strcpy(str, cstr);
    return tparm(str, value);
}
/* 
	setup terminal characteristics and allocate initial stuff 
*/
void *
rl_init(int cliIdx)
{
char *term;
int ret;
rl_t *rl=calloc(1, sizeof(*rl));

        /* initialize soem of the values */
        rl->maxh=DEF_HIST;       /* number of buffered commands */
        rl->maxl=DEF_LENGTH;     /* maximum command length */
        rl->prompt="tracker> ";
        rl->notty=0;
        rl->width=80;
        rl->maxpos=0;
        rl->histoff=0;
        
        /* callbacks */
        rl->cliIdx=cliIdx;
        
        /* sequence matching */
        rl->seqidx=0;
        

	if(!(rl->hist=hist_init(rl->maxh, rl->maxl, cliIdx))) return 0;

	/* allocate a new buffer */
	if(!(rl->buf=malloc(rl->maxl))) return 0;


        /* setup the terminal parameter for 'term '. Do this only once */
        if(!termInit) {
            termInit++;
	    term=strdup("xterm");
	    if(setupterm(term, 0, &ret)!=ERR)
	    {
                free(term);
	        bip="\007";
                kwb="\033\177";
                kwf="\033d";
                fw="\033f";
                bw="\033b";
		/* if any of these basics go back to fgets() */
		if(!(upN=mygetstr("cuu")) ||
		   !(downN=mygetstr("cud")) ||
		   !(leftN=mygetstr("cub")) ||
		   !(bol=mygetstr("cr")) ||
		   !(rightN=mygetstr("cuf")) ||
		   !(cod=mygetstr("ed"))) { rl->notty=1; return rl; }

		xenl=mygetflag("xenl");
		home=mygetstr("clear");
		kup=mygetstr("kcuu1");
		kdown=mygetstr("kcud1");
		kleft=mygetstr("kcub1");
		kright=mygetstr("kcuf1");
		kdel=mygetstr("kdch1");
		kbksp=mygetstr("kbs");
	    } else 
	    { 
		    trkdbg(0,0,1,"Unable to initialize 'term'\n");
	    }
        }
#ifdef OVER_TTY
	/* get window size */
	{
	struct winsize w;

		if (ioctl (in, TIOCGWINSZ, &w) == 0)
		{
			width=w.ws_col;
		}
		else /* use ENV */
		{
		char *ewidth;

			if ((ewidth = getenv ("COLUMNS")))
				width = atoi (ewidth);

			/* use what's in terminfo */
			if (width <= 0)
				width = tigetnum ("co");

		}

		if (width <= 1) width = 80;

	}
	/* set ourselves in the proper mode */
	{
		if(ioctl(in, TCGETA, &tio)) { notty=1; return 1;}

		stio=tio;

		tio.c_lflag &= ~(ICANON | ECHO);
		tio.c_iflag &= ~(ICRNL  | INLCR);
		tio.c_cc[VMIN] = 1;
		tio.c_cc[VTIME] = 0;
	}
#endif	
    rlShowPrompt(rl, 1);
    return rl;
}

void rl_shutdown(void *vrl)
{
rl_t *rl=(rl_t *)vrl;

    if(rl)  {
        if(rl->hist) hist_shutdown(rl->hist);
        free(rl);
    }
}

#define UP_HISTORY 	1001
#define DOWN_HISTORY	1002
#define CURSOR_LEFT	1003
#define CURSOR_RIGHT	1004
#define DELETE		1005
#define BACKSPACE	1006
#define KILLLINE	1007
#define LINEDONE	1008
#define KILLWORD	1009
#define KILLTOBOL	1010
#define KILLTOEOL	1011
#define GOTOBOL		1012
#define GOTOEOL		1013
#define CLRSCR		1014
#define REDRAW		1015
#define KILL_WORD_FORWARD	1016
#define WORD_BACKWARD		1017
#define WORD_FORWARD		1018
#define COMPLETE_LINE	1019 /* for completing line */
#define DEL		1020

#define NCTRL	16
static int ctrls[NCTRL][2]=
{
	{UP_HISTORY,	ctrl('P')},
	{DOWN_HISTORY,	ctrl('N')},
	{CURSOR_LEFT,	ctrl('B')},
	{CURSOR_RIGHT,	ctrl('F')},
	{DELETE	,	ctrl('D')},
	{BACKSPACE,	ctrl('H')},
	{LINEDONE,	ctrl('J')},
	{KILLWORD,	ctrl('W')},
	{KILLTOBOL,	ctrl('U')},
	{KILLTOEOL,	ctrl('K')},
	{GOTOBOL,	ctrl('A')},
	{GOTOEOL,	ctrl('E')},
	{CLRSCR,	ctrl('L')},
	{REDRAW,	ctrl('R')},
	{DEL,		'\177'},
	{LINEDONE,	'\r'},
};
#define NBIND (sizeof(codes)/sizeof(codes[0]))
static const int codes[]={
	UP_HISTORY,DOWN_HISTORY,CURSOR_LEFT,CURSOR_RIGHT,DELETE,
	BACKSPACE,KILLWORD,KILL_WORD_FORWARD,WORD_BACKWARD,WORD_FORWARD,
        UP_HISTORY,DOWN_HISTORY,CURSOR_LEFT,GOTOBOL,CURSOR_RIGHT,GOTOEOL
};
static const char **seqs[]={
	&kup,&kdown,&kleft,&kright,&kdel,
	&kbksp,&kwb,&kwf,&bw,&fw,
        &upN,&downN,&leftN,&bol,&rightN,&cod
};

static void buz(rl_t *rl) 
{
    cliPutStr(rl->cliIdx,bip);
}

static int
getinput(rl_t *rl)
{
int c=cliGetchar(rl->cliIdx);
uint32_t i;
int found=0;

    if(c>0) {

        trkdbg(3,0,0,"Checking out c=0x%02x[%c]\n", c, c);
        /* check the control characters */
        for(i=0;i<NCTRL;i++)
	        if(ctrls[i][1]==c) {
                    trkdbg(3,0,0,"Returning ctr code[%d]\n", i);
                    return ctrls[i][0];
                }

        /* check the keyboard sequences */
        rl->curseq[rl->seqidx++]=c;
        trkdbg(3,0,0,"c=%02x\n", c);
        for(i=0;i<NBIND;i++)
        {
        int j;

	        if(!*(seqs[i])) continue;
	        for(j=0;j<rl->seqidx;j++)
	        {
                        trkdbg(3,0,0,"%d- [0x%02x] vs [0x%02x]\n", j, (*seqs[i])[j], rl->curseq[j]);
		        if((*seqs[i])[j]==rl->curseq[j])
		        {
			        /* set found if we match the entire current input */
			        if(j==rl->seqidx-1) found=1;
			        if((*seqs[i])[j+1]=='\0') {
                                
                                    trkdbg(1,0,0,"Returning sequence code[%d]\n", i);
                                    rl->seqidx=0;
                                    return codes[i];
                                }
		        }
	        }
        }
        if(!found) {
                trkdbg(3,0,0,"returning c=0x%02x[%c]\n", c, c);
	        if(isprint(c)){
                    rl->seqidx=0;
		    return c;
                }
                buz(rl); 
                
                rl->seqidx=0;
        }
        else {
            return 0;
        }
    }
    trkdbg(3,0,0,"returning c=0x%02x\n", c, c);
    return c;
}

static void curboth(rl_t *rl, int n)
{
int curx=rl->curpos%rl->width;
int cury=rl->curpos/rl->width;
int newx=(rl->curpos+n)%rl->width;
int newy=(rl->curpos+n)/rl->width;

	if(newy > cury) cliPutStr(rl->cliIdx,mytparm(downN, newy-cury));
	else if(cury > newy) cliPutStr(rl->cliIdx,mytparm(upN, cury-newy));
	if(newx > curx) cliPutStr(rl->cliIdx,mytparm(rightN, newx-curx));
	else if(curx > newx) cliPutStr(rl->cliIdx,mytparm(leftN, curx-newx));
	rl->curpos+=n;
}

static void curleft(rl_t *rl, int n) { curboth(rl, -n); }
static void curright(rl_t *rl, int n) { curboth(rl, n); }

/* 
	This function clears the screen button. Displays the current buffer and
	sets the cursor at the proper position.
*/
static void
showbuf(rl_t *rl, int repos)
{
int max, i;
int pos=rl->curpos;

	/* clear to end of display from where we are now */
	cliPutStr(rl->cliIdx,cod);

	/* display the current buffer */
	for(i=rl->curpos; i<rl->maxpos; i+=max) {

		int c;

		max=rl->width-(i%rl->width);
		if(i+max > rl->maxpos) max=rl->maxpos-i;
		c=rl->buf[i+max];
		rl->buf[i+max]='\0';
		cliPutStr(rl->cliIdx,rl->buf+i);
		rl->buf[i+max]=c;
		if(!((i+max)%rl->width) && xenl) {

			cliPutStr(rl->cliIdx,"\n"); 
			cliPutStr(rl->cliIdx,bol);
		}
	}
	rl->curpos=rl->maxpos;
	if(repos) curleft(rl, rl->maxpos-pos);
}

static void rl_resetState(rl_t *rl)
{
    /* show the prompt */
    memset(rl->buf, 0, rl->maxl);
    strcpy(rl->buf, rl->prompt);
    rl->histoff=0;
    rl->curpos=rl->maxpos=strlen(rl->prompt);
}

void rlShowPrompt(void *vrl, int reset)
{
rl_t *rl=(rl_t*)vrl;

    if(reset) rl_resetState(rl);
    cliPutStr(rl->cliIdx,rl->buf);
    showbuf(rl, 0);    
}

void
rl_newChar(void *vrl)
{
rl_t *rl=(rl_t*)vrl;
int plen=strlen(rl->prompt);

    do {

		int key;

		switch((key=getinput(rl))) { 

		case UP_HISTORY: case DOWN_HISTORY:
		{
		int inc=(key==UP_HISTORY?1:-1);
		char *p;

			if((p=hist_getcmd(rl->hist, rl->histoff+inc)))
			{
				curleft(rl, rl->curpos-plen);
				strcpy(rl->buf+plen, p);
				rl->maxpos=strlen(rl->buf);
				showbuf(rl, 0);
				rl->curpos=rl->maxpos;
				rl->histoff+=inc;

			}else buz(rl);
		}
		break;
		case BACKSPACE: case DEL: case CURSOR_LEFT:
		{
			if(rl->curpos==plen) buz(rl);
			else
			{
				curleft(rl, 1);
				/* we need to reprint if backspace */
				if(key==BACKSPACE || key==DEL)
				{
					memmove(rl->buf+rl->curpos, rl->buf+rl->curpos+1, rl->maxl-rl->curpos-1);
					rl->maxpos--;
					showbuf(rl, 1);
				}
			}
		}
		break;
		case DELETE:
		{
			if(rl->curpos==rl->maxpos) buz(rl);
			else
			{
				memmove(rl->buf+rl->curpos, rl->buf+rl->curpos+1, rl->maxl-rl->curpos-1);
				rl->maxpos--;
				showbuf(rl, 1);
			}
		}
		break;
		case CURSOR_RIGHT:
		{
			if(rl->curpos==rl->maxpos) buz(rl);
			else { curright(rl, 1); }
		}
		break;
		case LINEDONE:
		{
                    char *p;
                    
			/* we're about to return, so set the cursor position */
			curright(rl, rl->maxpos-rl->curpos);
			cliPutStr(rl->cliIdx,"\r\n");
                        /* make any history substitutions */
		        if((p=hist_cmd(rl->hist, rl->buf+plen)))
		        {
			        /* hist_cmd() return a pointer to the actual history
			           entry, so make a copy to buf and return to user */
                                trkdbg(1,0,0,"rl command '%s' replaced by '%s'\n", rl->buf+plen, p);
			        strcpy(rl->buf+plen,p);
			        if(cliNewCmd(rl->buf+plen, rl->cliIdx)) {
                                    rl_resetState(rl);
                                    rlShowPrompt(rl, 0);
		                }
                                else rl_resetState(rl);
                        }
                        else {
                            trkdbg(1,0,0,"rl command '%s' NOT replaced by history!\n", rl->buf+plen);
                            rl_resetState(rl);
                            rlShowPrompt(rl, 0);
                        }
		}
                break;
		/* erase entire line . Currently not linked to any keys */
		case KILLLINE:
		{
			curleft(rl, rl->curpos-plen);
			rl->maxpos=plen;
			rl->buf[plen]='\0';
			showbuf(rl, 1);
		}
                break;
		/* erase the current word */
		case KILLWORD:
		{
			/* if we are at the start of the line , bip */
			if(rl->curpos==plen) buz(rl);
			else
			{
			int i=rl->curpos-1;

				/* if the cursor sits on a white character already 
				   find the first non white one */
				while(!isalnum(rl->buf[i])&&i>plen) i--;
				/* skip back untill beginning of line or white again */
				while(isalnum(rl->buf[i])&&i>plen) i--;
				if(i<rl->maxpos && !isalnum(rl->buf[i])) i++;
				/* move every backward */
				memmove(rl->buf+i, rl->buf+rl->curpos, rl->maxl-rl->curpos);
				curleft(rl, rl->curpos-i);
				rl->maxpos=strlen(rl->buf);
				showbuf(rl, 1);
			}
		}
		break;
		case KILLTOBOL:
		{
			memmove(rl->buf+plen, rl->buf+rl->curpos, rl->maxl-rl->curpos);
			curleft(rl, rl->curpos-plen);
			rl->maxpos=strlen(rl->buf);
			showbuf(rl, 1);
		}
		break;
		case KILLTOEOL:
		{
			rl->buf[rl->curpos]='\0';
			rl->maxpos=strlen(rl->buf);
			showbuf(rl, 1);
		}
		break;
		case GOTOBOL: { curleft(rl, rl->curpos-plen); } break;
		case GOTOEOL: { curright(rl, rl->maxpos-rl->curpos); } break;
		case CLRSCR: 
		{ 
			if(home) {

				int i=rl->curpos;

				cliPutStr(rl->cliIdx,home); 
				rl->curpos=0;
				showbuf(rl, 0);
				rl->curpos=rl->maxpos;
				curleft(rl, rl->maxpos-i);

			} else buz(rl); 

		} break;
				
		case REDRAW: { } break;  /* do nothing */
		case WORD_FORWARD:
			/* if we are at the start of the line , bip */
			if(rl->curpos==rl->maxpos) buz(rl);
			else
			{
			int i=rl->curpos;

				/* if the cursor sits on a white character already 
		   		find the first non white one */
				while(!isalnum(rl->buf[i])&&i<rl->maxpos) i++;
				/* scip back untill beginning of line or white again */
				while(isalnum(rl->buf[i])&&i<rl->maxpos) i++;
				curright(rl, i-rl->curpos);
			}
		break;

		case WORD_BACKWARD:
			/* if we are at the start of the line , bip */
			if(rl->curpos==plen) buz(rl);
			else
			{
			int i=rl->curpos;

				/* if the cursor sits on a white character already 
		   		   find the first non white one */
				if(i>plen) i--;
				while(!isalnum(rl->buf[i])&&i>plen) i--;
				/* scip back untill beginning of line or white again */
				while(isalnum(rl->buf[i])&&i>plen) i--;
				while(!isalnum(rl->buf[i])&&i>plen) i++;
				curleft(rl, rl->curpos-i);
			}
		break;

		case KILL_WORD_FORWARD:
			/* if we are at the start of the line , bip */
			if(rl->curpos==rl->maxpos) buz(rl);
			else
			{
			int i=rl->curpos;

				/* if the cursor sits on a white character already 
		   		find the first non white one */
				while(!isalnum(rl->buf[i])&&i<rl->maxpos) i++;
				/* scip back untill beginning of line or white again */
				while(isalnum(rl->buf[i])&&i<rl->maxpos) i++;
				while(!isalnum(rl->buf[i])&&i<rl->maxpos) i++;
				/* keep one space */
				if(i<rl->maxpos && isalnum(rl->buf[i])) i--;
				/* move every backward */
				memmove(rl->buf+rl->curpos, rl->buf+i, rl->maxl-i);
				rl->maxpos=strlen(rl->buf);
				showbuf(rl, 1);
			}
		break;

		default: 
		{
                        if (key == -1) {
                            closeCli(rl->cliIdx);
                        }
                        else if(key) {
			    if(rl->maxpos==rl->maxl) buz(rl);
			    else
			    {
				    memmove(rl->buf+rl->curpos+1, rl->buf+rl->curpos, rl->maxl-rl->curpos-1);
				    rl->buf[rl->curpos]=key;
				    rl->maxpos++;
				    showbuf(rl, 1);
				    curright(rl, 1);
			    }
                        }
		}
		break;
		}
	} while(0);
}

#ifdef MAIN
main()
{
        int error = 0;

	if(!rl_init(">> ", 1024, 100)) exit(0);

	printf("notty=%d\n", notty);

	while(1) printf("command=(%s)\n", rl_getline(&error));
}
#endif
