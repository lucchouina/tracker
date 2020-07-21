#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "trkdbg.h"
#include "trkmgrRl.h"

typedef struct hist_s {
    int nbuf;
    char **cmds;
    int *ctag;
    int curidx;
    int curtag;
    int maxl;
    int cliIdx;
} hist_t;

static void
hist_list(hist_t *h)
{
int i;

	for(i=0;i<h->curidx;i++)
	{
		cliPrt(h->cliIdx, "%3d: %s\n", h->ctag[i], h->cmds[i]);
	}
}

static void
hist_setmax(hist_t *h, int maxh)
{
	if(maxh>DEF_MAXHIST || maxh<=0)
	{ cliPrt(h->cliIdx, "%d invalid, valid range is [1..%d]\n", maxh, DEF_MAXHIST); return;}

	if(maxh!=h->nbuf)
	{
	char **nc;
	int *nt;

		if((nc=(char**)malloc(sizeof(char*)*maxh)))
		{
			if((nt=(int*)malloc(sizeof(int)*maxh))) 
			{
				/* move the older lists around ? */
				if(h->curidx) 
				{
				int i, start=0, j;

					if(maxh<h->curidx) start=h->curidx-maxh;

					for(i=0;i<start;i++) free(h->cmds[i]);

					for(i=start,j=0;j<maxh&&i<h->curidx;i++,j++)
					{
						nt[j]=h->ctag[i];
						nc[j]=h->cmds[i];
					}
					h->curidx=j;
					free(h->cmds);
					free(h->ctag);
				}
				h->cmds=nc;
				h->ctag=nt;
				h->nbuf=maxh;
			}
			else free(nc);
		}
	}
}

void * 
hist_init(int maxh, int maxc, int idx)
{
hist_t *h=calloc(1, sizeof *h);

    h->nbuf=0;
    h->cmds=NULL;
    h->ctag=NULL;
    h->curidx=0;
    h->curtag=0;
    h->maxl=0;
    h->maxl=maxc;
    h->cliIdx=idx;
    hist_setmax(h, maxh);
    return h;
}

void hist_shutdown(void *h)
{
    if(h) free(h);
}

/*
	Add a new command to history list.
*/
static char *
hist_add(hist_t *h, char *s1, char *s2)
{
int len;
char *pt;

	/* make some space for the new history line */
	len=strlen(s1)+(s2?strlen(s2):0);
	if(len>h->maxl) len=h->maxl;
	if(!(pt=malloc(len+1)))
	{ trkdbg(0,0,0,"history: memory allocation error!\n"); return NULL;}

	strcpy(pt, s1);
	if(s2) strncat(pt,s2,h->maxl-strlen(s1));

	/* get rid of the oldest one ? */
	if(h->curidx==h->nbuf)
	{
		/* free oldest */
		free(h->cmds[0]);
		/* move over pointers and indexes */
		memmove(&h->cmds[0], &h->cmds[1], (h->nbuf-1)*sizeof(h->cmds[0]));
		memmove(&h->ctag[0], &h->ctag[1], (h->nbuf-1)*sizeof(h->ctag[0]));
		h->curidx--;
	}

	h->cmds[h->curidx]=pt;
	h->ctag[h->curidx]=(++(h->curtag));
	if(h->curidx<h->nbuf) h->curidx++;
	return pt;
}

/*
	hook for the command interface.
	get me the command at curidx-offset
*/
char *
hist_getcmd(void *vh, int off)
{
static char nstr[]="\0";
hist_t *h=(hist_t*)vh;
	if(off<=h->curidx && off>=0)
	{
		return off ? h->cmds[h->curidx-off] : nstr;
	}
	else return 0;
}


/*
	get a previous command from the history and place it
	in the current input.

	idx is the index in the current history list.
	xtra is whatever the user entered after the history command.
*/
static char*
repeat(hist_t *h, int idx, char *xtra)
{
char *p=hist_add(h, h->cmds[idx],xtra);

	cliPrt(h->cliIdx, "%s\n", p);
	return p;
}

/*
	scan backward and find a tg.
*/
static int
getidx(hist_t *h, int tag)
{
int i;

	for(i=h->curidx;i>=0;i--) if(h->ctag[i]==tag) break;
	return i;
}

/*
	pass the command through to see if we need to do some history 
	gymnastics...
*/
char *
hist_cmd(void *vh, char *cmd)
{
hist_t *h=(hist_t*)vh;
char *tok=cmd;

	while(*cmd==' '||*cmd=='\t') cmd++;

	if(!*cmd) return 0;

	/* command 'h' or 'history' */
	/* ugly but I don't want to use strtok... */
	if( ( ((cmd[0]=='h') && 
	       ( (cmd[1]==' ') || (cmd[1]=='\t') || (!cmd[1]) )))
	    || ((!strncmp(cmd,"history", 7)) && 
		( (cmd[7]==' ') || (cmd[7]=='\t') || (!cmd[7]) )))
	{
		char *pt=cmd;
		
		while(*pt) if(isdigit(*pt)) break; else pt++;

		/* check to see if we are changing the number of lines */
		if(*pt)
		{
		int n;
			sscanf(pt,"%d", &n);
			hist_setmax(h, n);
		}
		/* show history */
		else hist_list(h);

		return 0;
	}
	else if(tok[0]=='!')
	{
		/* we most have at least one entry for !! to be valid */
		if(tok[1]== '!')
		{
			if(h->curidx) return repeat(h, h->curidx-1, tok+2);
		}
		else
		{
		int n;

			/* number ? */
			if(sscanf(tok+1, "%d", &n)==1)
			{
			int rel=0;


				tok++;
				if(*tok=='-') {n=(-n); rel=1; tok++;}

				while(isdigit(*tok)) tok++;

				/* absolute index */
				if(!rel)
				{
				int nidx=getidx(h, n);

					if(nidx>=0) return repeat(h, nidx,tok);
				}
				/* relative backward */
				else
				{
					if(h->curidx>n) return repeat(h, h->curidx-n, tok);
				}
			}
			/* string match ? */
			else
			{
			char *pt=tok+1;
			int nc,i;

				while(*pt!=' '&&*pt!='\t'&&*pt) pt++;
				nc=pt-tok-1;
				for(i=h->curidx-1;i>=0;i--)
				{
					if(!strncmp(h->cmds[i], tok+1, nc))
						return repeat(h, i, tok+nc+1);
				}
			}
		}
		cliPrt(h->cliIdx, "Invalid history specification.\n");
		return 0;
	}
	else return hist_add(h, cmd,NULL);
}
