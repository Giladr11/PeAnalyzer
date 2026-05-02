#include "include/api.h"
#include <stdlib.h> 
#include <stdio.h>

//========================================================Main-PE-Analyzer========================================================

int main(int argc, char* argv[]) 
{
    // Input Validation
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <file.exe>\n", argv[0]);
        return ERROR_STATUS;
    }
    
    // PE Analyzer Initialization Phase
    HANDLER* handler = initPEAnalyzer(argv[1]);
    if (!handler)
    {
        printf("[-] Error: Failed to Initialize PE-Analyzer!\n");
        return ERROR_STATUS;
    }

    // Parsing Phase
    printf("Initiating Parsing Phase...\n\n");

    int status = MainPEHeadersParser(handler);

    if (status == SUCCESS_STATUS)
    {
        fprintf(stdout, "[+] Headers Parsing Finished Succesfully!\n");
    }
    else 
    {
        fprintf(stderr, "[-] Error: Parsing failed!\n");
        return ERROR_STATUS;
    }
    
    // Context Dumping Phase
    printf("\nInitiating Context Dumping Phase...\n\n");




    // Cleaning Phase
    FreeAnalysis(handler->PEContext->Analysis);
    FreeParsedExportDirectoryAnalysis(handler->PEContext->Analysis->ParsedExportDirectory);
    free(handler->PEContext->Headers);
    
    free(handler->DiskPEImage);
    free(handler->PEContext);
    free(handler);

    return 0;
}
