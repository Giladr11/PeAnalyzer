#include "include/api.h"
#include <stdlib.h> 
#include <stdio.h>

//========================================================Main-PE-Analyzer========================================================

// Execute Parsing Phase
int ExecuteParsingPhase(HANDLER* handler)
{
    fprintf(stdout, "[PHASE] Initiating Parsing Phase...\n");
    fprintf(stdout, "===================================\n");

    int headers_parser_status = MainPEHeadersParser(handler);

    if (headers_parser_status == ERROR_STATUS)
    {
        fprintf(stderr, "[-]\nError: Headers Parsing has Failed!\n\n");
        return ERROR_STATUS;
    }
       
    fprintf(stdout, "\n[++] Headers Parsing has Completed Succesfully!\n\n");

    return SUCCESS_STATUS;
}

// Execute Context Dumping Phase
int ExecuteDumpingPhase(HANDLER* handler)
{
    // Context Dumping Phase
    fprintf(stdout, "\n[PHASE] Initiating Context Dumping Phase...\n");
    fprintf(stdout, "===========================================\n");

    int context_dumper_status = MainPEContextDumper(handler->PEContext);

    if (context_dumper_status == ERROR_STATUS)
    {
        fprintf(stderr, "[-]\nError: Context Dumping has Failed!\n");
        return ERROR_STATUS;
    }

    fprintf(stdout, "[++] Context Dumping has Completed Succesfully!\n");

    return SUCCESS_STATUS;
}


int main(int argc, char* argv[]) 
{
    // Input Validation
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <file.exe>\n", argv[0]);
        return ERROR_STATUS;
    }
    
    // PE Initialization Phase
    char* pe_path = argv[1];
    HANDLER* handler = initPEAnalyzer(pe_path);
    if (!handler)
    {
        fprintf(stderr, "[-] Error: Failed to Initialize PE-Analyzer!\n");
        return ERROR_STATUS;
    }

    // Parsing Phase
    int status = ExecuteParsingPhase(handler);
    if (status == ERROR_STATUS)
    {
        return ERROR_STATUS;
    }
    
    // Dumping Phase
    status = ExecuteDumpingPhase(handler);
    if (status == ERROR_STATUS)
    {
        return ERROR_STATUS;
    }

    // Cleaning Phase
    clean_heap(handler);

    printf("\n=======================PE-Analysis-Completed=======================\n");  

    return SUCCESS_STATUS;
}
