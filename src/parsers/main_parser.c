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
    
    fprintf(stdout, "[+] Sections Parsing completed Successfully!\n");


    // Optional Header Parsing
    int32_t nt_offset = handler->PEContext->Headers->DosHeader->e_lfanew;
    MY_IMAGE_NT_HEADERS64* pTempNTHeaders = (MY_IMAGE_NT_HEADERS64*)(RVA_TO_VA(handler->DiskPEImage->DiskImageBase, nt_offset));

    TABLES_ANALYSIS_RESULTS OptionalHeaderResults = OptionalHeaderParser(handler, &pTempNTHeaders->OptionalHeader);

    if (OptionalHeaderResults.status == STATUS_ERROR)
    {   
        fprintf(stderr, "[-] Error: Optional Header analysis Failed!\n");

        FreeAnalysis(OptionalHeaderResults.Analysis);
        return STATUS_ERROR;
    }
    
    // Map DataDirectory entries *(Export/Import)*
    handler->PEContext->Headers->ExportDirectory = OptionalHeaderResults.ExportDirectory;

    // Map Import Descriptor if successfully resolved
    if (OptionalHeaderResults.ImportDescriptors)
    {
        handler->PEContext->Headers->ImportDescriptors = OptionalHeaderResults.ImportDescriptors;   
    }

    // transfer Pointer OwnerShip 
    handler->PEContext->Analysis = OptionalHeaderResults.Analysis;
    
    // Detach double pointer to memory
    OptionalHeaderResults.Analysis = NULL;

    return STATUS_SUCCESS;
}