#include "include/internals.h"


//============================================================Main-Dumpers============================================================

STATUS MainPEContextDumper(PE_CONTEXT* PEContext) 
{
    
    if (DumpDosHeader(PEContext->Headers->DosHeader) == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: Failed to Dump Dos-Stub\n");
        return ERROR_STATUS;
    }

    if (DumpDosStub(PEContext->Headers->DosStub) == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: Failed to Dump Dos-Stub\n");
        return ERROR_STATUS;
    }
    
    if (DumpNTHeaders(PEContext) == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: Failed to Dump Dos-Stub\n");
        return ERROR_STATUS;
    }

    if (DumpSectionHeader(PEContext->Headers->SectionHeaders, PEContext->Headers->FileHeader->NumberOfSections) == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: Failed to Dump Dos-Stub\n");
        return ERROR_STATUS;
    }

    return SUCCESS_STATUS;
}
