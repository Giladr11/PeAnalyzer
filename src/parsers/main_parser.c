#include "include/internals.h"


//============================================================MAIN-Parsers============================================================

int MainPEHeadersParser(HANDLER* handler)
{
    if (DosHeaderParser(handler) != STATUS_SUCCESS){
        return STATUS_ERROR;
    }

    fprintf(stdout, "[+] Dos Header parsing completed Successfully!\n");

    if (NTHeadersParser(handler) != STATUS_SUCCESS) {
        return STATUS_ERROR;
    }
    
    fprintf(stdout, "[+] NT Headers Parsing completed Successfully!\n");

    if (SectionHeadersParser(handler) != STATUS_SUCCESS) {
        return STATUS_ERROR;
    }

    fprintf(stdout, "[+] Sections Parsing completed Successfully\n");

    return STATUS_SUCCESS;
}