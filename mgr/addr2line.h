#ifndef __addr2line_h__
#define __addr2line_h__
void *addAddrPid(pid_t pid, char *prog);
void addrClose(void *vpm);
char *addr2line(void *vpm, size_t addr);
#endif
