#include "include/internals.h"


//============================================================Main-Dumpers============================================================

int MainPEContextDumper(PE_CONTEXT* PEContext) {
    
    int dump_status;

    dump_status = DumpDosStub(PEContext);
    if (dump_status == ERROR_STATUS)
    {
         fprintf(stderr, "[-] Error: Failed to Dump Dos-Stub\n");
        return ERROR_STATUS;
    }

    return SUCCESS_STATUS;
}
