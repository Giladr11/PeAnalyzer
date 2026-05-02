#include "include/internals.h"

//============================================================Headers-Dumping============================================================

int DosHeaderDumping(PE_CONTEXT* PEContext)
{


    return SUCCESS_STATUS;
}


// Extract DOS-Stub Header 
int DumpDosStub(PE_CONTEXT* PEContext) 
{
    const char* dos_stub = PEContext->Headers->DosStub;

    if (!dos_stub)
    {
        return ERROR_STATUS;
    }

    fprintf(stdout, "[#] Dos-Stub Message: '%s'\n\n", dos_stub);

    return SUCCESS_STATUS;
}
