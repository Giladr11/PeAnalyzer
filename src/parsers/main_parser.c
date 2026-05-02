#include "include/internals.h"

//============================================================Main-Parsers============================================================

int MainPEHeadersParser(HANDLER* handler)
{
    // Dos Header Parsing
    if (DosHeaderParser(handler) == ERROR_STATUS){
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Dos Header parsing completed Successfully!\n");
    
    // Extract and Print the Dos Stub Message
    ExtractDosStub(handler);
    
    // NT Headers Parsing *(Only File Header. Optional Header is parsed after sections)*
    if (NTHeadersParser(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] NT Headers Parsing completed Successfully!\n");

    // Section Headers Parsing (.idata .text .)
    if (SectionHeadersParser(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Sections Parsing completed Successfully!\n");

    // Optional Header Parsing (Exports & Imports)
    if (OptionalHeaderInitializer(handler) == ERROR_STATUS) {
        return ERROR_STATUS;
    }
    fprintf(stdout, "[+] Optional Header Parsing completed Successfully!\n");


    return SUCCESS_STATUS;
}