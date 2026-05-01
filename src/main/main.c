#include "include/api.h"
#include <stdlib.h> 
#include <stdio.h>


int main(int argc, char* argv[]) 
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <file.exe>\n", argv[0]);
        return STATUS_ERROR;
    }
    
    size_t PE_size = 0;

    void* filebase = LoadPEDiskImage(argv[1], &PE_size);
    if (!filebase)
    {
        return STATUS_ERROR;
    }
    
    HANDLER* handler = CreateHandler(filebase, PE_size);
    if (!handler)
    {
        return STATUS_ERROR;
    }

    printf("Initiating PE Headers Parsing...\n");

    int status = MainPEHeadersParser(handler);

    if (status == STATUS_SUCCESS)
    {
        fprintf(stdout, "[+] Headers Parsing Finished Succesfully!\n");
    }
    else 
    {
        fprintf(stderr, "[-] Error: Parsing failed!\n");
        return STATUS_ERROR;
    }
    
    // Cleaning heap pointers
    FreeAnalysis(handler->PEContext->Analysis);
    FreeParsedExportDirectoryAnalysis(handler->PEContext->Analysis->ParsedExportDirectory);
    free(handler->PEContext->Headers);
    
    free(handler->DiskPEImage);
    free(handler->PEContext);
    free(handler);

    return 0;
}
