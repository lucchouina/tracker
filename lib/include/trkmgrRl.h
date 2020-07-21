#define DEF_HIST                100	/* default number of history commands */
#define DEF_LENGTH              1024	/* default command length */
#define DEF_MAXHIST		1000	/* maximum number of history commands */
#define PRINT_BEEP              (char *)-1
#define DRAW_NEW_ENTIRE_LINE    (char *)0
char *hist_getcmd(void *h, int off);
char *hist_cmd(void *h, char *cmd);
void *hist_init(int maxh, int maxc, int cliIdx);
void  hist_shutdown(void *h);
