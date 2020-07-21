#include <stdlib.h>
#include "trkdbg.h"

extern int summary;

__inline__ static char typeChar(resType_t type)
{
    switch(type) {
    
        case RESTYPE_MEMORY: return 'm';
        case RESTYPE_FILE: return 'f';
        default: return '?';
    }
}
#define voffset(p, o) (void*)((char *)p+o)

static void diveAndPrint(int cliIdx, int clientIdx, int idx, int indent, int maxEntry, void **vector, size_t *total)
{
    int i, size, is64=CLIENT_POINTER_SIZE(clientIdx)==8?1:0;
    uint32_t *tref32;
    uint64_t *tref64;
    char t;
    
    /* for all the entries at this indent level */
    while(idx < maxEntry) {
    
        tref32=voffset(vector[idx],RPTHEADERSIZE);
        tref64=voffset(vector[idx],RPTHEADERSIZE);
        t=typeChar(((int*)vector[idx])[1]);

        size=0;
        /* count all entries with similar PC and increment total size */
        for(i=idx; i<maxEntry; i++) {
           if (is64) {
                uint64_t *t64=voffset(vector[i],RPTHEADERSIZE);
                if(t64[indent]!=tref64[indent]) break;
            }
            else {
                uint32_t *t32=voffset(vector[i],RPTHEADERSIZE);
                if(t32[indent]!=tref32[indent]) break;
            }
            size += RPTSIZE(vector[i]);
        }
        /* tally Total */
        if(total) *total+=size;

        /* print that entry */
        if(!summary && size > 0) {
            if (is64) {
                cliPrt(cliIdx, "%*s0x%016llx [%d] %c\n", indent*4, "", tref64[indent], size, indent? ' ': t);
            }
            else {
                cliPrt(cliIdx, "%*s0x%08x [%d] %c\n"   , indent*4, "", tref32[indent], size, indent? ' ': t);
            }
        }
        /* print all the other sub-levels */
        while(indent<MAXCALLERS-1) {
            if(is64) { if(!tref64[indent+1]) break; }
            else { if(!tref32[indent+1]) break; }
            diveAndPrint(cliIdx, clientIdx, idx, indent+1, i, vector, 0);
            break;
        }
        idx=i;
    }
}

void buildShowTree(int cliIdx, int clientIdx, int nentries, void **vector, size_t *total)
{
    *total=0;
    diveAndPrint(cliIdx, clientIdx, 0, 0, nentries, vector, total);
    cliPrt(cliIdx, "Total allocated : %d\n", *total);
}
