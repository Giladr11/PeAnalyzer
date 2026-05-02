#include "include/internals.h"

//============================================================Main-Parsers============================================================

int MainPEHeadersParser(HANDLER* handler)
{
    // Dos Header Parsing
    if (DosHeaderParser(handler) == ERROR_STATUS){
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Dos Header parsing has completed Successfully!\n");
    

    // Extract and Print the Dos Stub Message
    DosStubParser(handler);
    

    // NT Headers Parsing *(Only File Header. Optional Header is parsed after sections)*
    if (NTHeadersParser(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] NT Headers Parsing has completed Successfully!\n");


    // Section Headers Parsing (.idata .text .)
    if (SectionHeadersParser(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Section Headers Parsing has completed Successfully!\n");


    // Optional Header Parsing (Exports & Imports)
    if (OptionalHeaderInitializer(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Optional Header Parsing has completed Successfully!\n");


    return SUCCESS_STATUS;
}
