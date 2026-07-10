#include "include/internals.h"
#include "include/pe_headers.h"

//============================================================Headers-Dumping============================================================

STATUS DumpDosHeader(MY_IMAGE_DOS_HEADER* dos_header)
{
    printf("=====================Dos-Header-Dumping=====================\n");
    printf("e_magic:    0x%04X\n", dos_header->e_magic);
    printf("e_cblp:     %u\n", dos_header->e_cblp);
    printf("e_cp:       %u\n", dos_header->e_cp);
    printf("e_crlc:     %u\n", dos_header->e_crlc);
    printf("e_cparhdr:  %u\n", dos_header->e_cparhdr);
    printf("e_minalloc: %u\n", dos_header->e_minalloc);
    printf("e_maxalloc: %u\n", dos_header->e_maxalloc);
    printf("e_ss:       0x%04X\n", dos_header->e_ss);
    printf("e_sp:       0x%04X\n", dos_header->e_sp);
    printf("e_csum:     0x%04X\n", dos_header->e_csum);
    printf("e_ip:       0x%04X\n", dos_header->e_ip);
    printf("e_cs:       0x%04X\n", dos_header->e_cs);
    printf("e_lfarlc:   0x%04X\n", dos_header->e_lfarlc);
    printf("e_ovno:     %u\n", dos_header->e_ovno);

    printf("e_oemid:    %u\n", dos_header->e_oemid);
    printf("e_oeminfo:  %u\n", dos_header->e_oeminfo);

    printf("e_lfanew:   0x%08X\n", dos_header->e_lfanew);

    printf("e_res: ");
    for (int i = 0; i < 4; i++)
        printf("0x%04X ", dos_header->e_res[i]);
    printf("\n");

    printf("e_res2: ");
    for (int i = 0; i < 10; i++)
        printf("0x%04X ", dos_header->e_res2[i]);
    printf("\n");

    return SUCCESS_STATUS;
}

// Extract DOS-Stub Header 
STATUS DumpDosStub(char* dos_stub) 
{
    printf("\n=====================Dos-Stub-Dumping========================\n");

    if (!dos_stub)
    {
        return ERROR_STATUS;
    }

    fprintf(stdout, "[#] Dos-Stub Message: '%s'\n\n", dos_stub);

    return SUCCESS_STATUS;
}

STATUS DumpNTHeaders(PE_CONTEXT* PeContext)
{
    printf("\n=============NT-Headers-Dumping=========\n");
    printf("PE Signature: 0x%04X\n" , PeContext->Headers->NtHeaders->Signature);

    printf("\n==========File-Header-Dumping===========\n");
    if (DumpFileHeader(PeContext->Headers->FileHeader) == ERROR_STATUS)
    {
        fprintf(stderr, "Failed to dump File Header...\n");
        return ERROR_STATUS;
    }

    printf("\n========Optional-Header-Dumping=========\n");
    if (DumpOptionalHeader(PeContext->Headers->OptionalHeader) == ERROR_STATUS)
    {
        fprintf(stderr, "Failed to dump Optional Header...\n");
        return ERROR_STATUS;
    }

    return SUCCESS_STATUS;
}
