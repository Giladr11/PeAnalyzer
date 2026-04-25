#include "include/internals.h"


//============================================================Imports-Parsers============================================================

// Import Descriptors Parser *(INT/IAT per DLL)* 
TABLES_ANALYSIS_RESULTS ImportDescriptorsParser(HANDLER* handler, MY_IMAGE_IMPORT_DESCRIPTOR* pTempImportDescriptors)
{
    TABLES_ANALYSIS_RESULTS ERROR_RESULT = {.status=STATUS_ERROR};
    
    ANALYSIS_CONTEXT* pTempAnalysisImportResult = calloc(1, sizeof(ANALYSIS_CONTEXT));
    if (!pTempAnalysisImportResult) 
    {
        return ERROR_RESULT;
    }

    // Allocate inner ParsedImportDescriptors
    pTempAnalysisImportResult->ParsedImportDescriptors = calloc(1, sizeof(PE_PARSED_IMPORT_DESCRIPTOR)); // free in main()
    if (!pTempAnalysisImportResult->ParsedExportDirectory) 
    {
        free(pTempAnalysisImportResult);
        return ERROR_RESULT;
    }

    uint32_t* TempINT = NULL;
    uint32_t* TempIAT = NULL;
    uint32_t iImportDescriptor = 0;

    while (pTempImportDescriptors->Name != 0)
    {
        char* dllName = (char*)RVA_TO_VA(handler->PEDiskImage->DiskImageBase, pTempImportDescriptors->Name);

        if (!dllName || dllName[0] == '\0')
        {
            fprintf(stderr, "[-] Error: DLL Name Doesnt Exist..\n");

            return ERROR_RESULT;
        }

        if (pTempImportDescriptors->FirstThunk == 0)
        {
            fprintf(stderr, "[-] Error: Invalid IAT RVA..\n");

            return ERROR_RESULT;
        }

        uint32_t INT_RVA = pTempImportDescriptors->OriginalFirstThunk;
        uint32_t IAT_RVA = pTempImportDescriptors->FirstThunk;

        if (INT_RVA)
        {
            TempINT = (uint32_t*)RVA_TO_VA(handler->PEDiskImage->DiskImageBase, pTempImportDescriptors->OriginalFirstThunk);
        }    
        else {
            fprintf(stderr, "[*] Warning: Missing INT, using IAT as fallback..\n");
        }

        TempIAT = (uint32_t*)RVA_TO_VA(handler->PEDiskImage->DiskImageBase, pTempImportDescriptors->FirstThunk);


        // Initialize Results
        PE_PARSED_IMPORT_DESCRIPTOR TempImportDescriptor = {
            .DllName = dllName,
            .INT = (MY_IMAGE_THUNK_DATA64 *)TempINT,
            .IAT = (MY_IMAGE_THUNK_DATA64 *)TempIAT,
        };

        // Parse INT & IAT for A DLL
        STATUS status = ParseThunkTables(handler, &TempImportDescriptor);

        if (status == STATUS_ERROR)
        {
            fprintf(stderr, "[-] Error: Failed to Parse (IAT/INT) for DLL: %s\n", dllName);
            return ERROR_RESULT;
        }

        pTempAnalysisImportResult->ParsedImportDescriptors[iImportDescriptor] = TempImportDescriptor;
        
        // Move to next Descriptor in memory..
        pTempImportDescriptors++;
        iImportDescriptor++;
    }
    
    return (TABLES_ANALYSIS_RESULTS){
        .ExportDirectory   = NULL,
        .ImportDescriptors = pTempImportDescriptors,
        .Analysis          = pTempAnalysisImportResult,
        .status            = STATUS_SUCCESS
    };
}

// Generic (INT & IAT) Parser
STATUS ThunkTablesParser(HANDLER* handler, PE_PARSED_IMPORT_DESCRIPTOR* pTempParsedImportDescriptors)  
{
    
    
}
