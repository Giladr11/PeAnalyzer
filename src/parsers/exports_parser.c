#include "include/internals.h"


//============================================================Exports-Parsers============================================================

// Export Table Parser *(EAT)* 
TABLES_ANALYSIS_RESULTS ExportDirectoryParser(HANDLER* handler, MY_IMAGE_EXPORT_DIRECTORY* pTempExportDirectory)
{   
    TABLES_ANALYSIS_RESULTS ERROR_RESULT = {.status=ERROR_STATUS};

    if (!pTempExportDirectory)
        return ERROR_RESULT;

    if (pTempExportDirectory->NumberOfNames > 0 && pTempExportDirectory->AddressOfNames == 0)
        return ERROR_RESULT;

    if (pTempExportDirectory->NumberOfNames > 0 && pTempExportDirectory->AddressOfNameOrdinals == 0)
        return ERROR_RESULT;

    if (pTempExportDirectory->NumberOfFunctions > 0 && pTempExportDirectory->AddressOfFunctions == 0)
        return ERROR_RESULT;
    
    // Initialize Results 
    ANALYSIS_CONTEXT* pTempAnalysisExportResult = {0};
    
    // Store Results
    ANALYSIS_CONTEXT* pTempAnalysis = calloc(1, sizeof(ANALYSIS_CONTEXT));
    
    if (!pTempAnalysis) 
    {
        return ERROR_RESULT;
    }
    
    pTempAnalysisExportResult = EATParser(handler, pTempExportDirectory);
       
    if (!pTempAnalysisExportResult)
    {   
        free(pTempAnalysis);
        free(pTempAnalysisExportResult->ParsedExportDirectory);
        free(pTempAnalysisExportResult);
        return ERROR_RESULT;
    }

    // Transfer ownership (Analysis->ParsedExportDirectory -> data ParsedExportDirectoryResult points to)
    pTempAnalysis->ParsedExportDirectory = pTempAnalysisExportResult->ParsedExportDirectory;

    pTempAnalysisExportResult->ParsedExportDirectory = NULL;

    // Free temporary container (no longer owns any heap data)
    free(pTempAnalysisExportResult);

    return (TABLES_ANALYSIS_RESULTS){
        .ExportDirectory   = pTempExportDirectory,
        .ImportDescriptors = NULL,
        .Analysis          = pTempAnalysis,
        .status            = SUCCESS_STATUS
    };
}


// EAT Parser & Validator & Store in ParsedExportDirectoryResults.Analysis (Name -> Ordinal -> Ordinal_Conversation (EAT_index) -> EAT[EAT_index])
ANALYSIS_CONTEXT* EATParser(HANDLER* handler, MY_IMAGE_EXPORT_DIRECTORY* pTempExportDirectory) 
{   
    ANALYSIS_CONTEXT* ERROR_RESULT = NULL;

    //Resolve EAT VA 
    uint32_t* TempEAT = (uint32_t*)RVA_TO_VA(handler->DiskPEImage->DiskImageBase,
                                             pTempExportDirectory->AddressOfFunctions);

    // Resolve AddressOfNames VA
    uint32_t* TempAddressOfNames = (uint32_t*)RVA_TO_VA(handler->DiskPEImage->DiskImageBase,
                                                        pTempExportDirectory->AddressOfNames);
    
    // Resolve AddressOfNameOrdinals VA
    uint32_t* TempAddressOfNameOrdinals = (uint32_t*)RVA_TO_VA(handler->DiskPEImage->DiskImageBase,
                                                               pTempExportDirectory->AddressOfNameOrdinals);
    
    // Array Sizes
    uint32_t EATCount = pTempExportDirectory->NumberOfFunctions;
    uint32_t NamesTableCount = pTempExportDirectory->NumberOfNames;
    uint32_t base_ordinal = pTempExportDirectory->Base;

    // Store results in ParsedExportDirectoryResults.Analysis->ParsedExportDirectory->EAT ParsedExportDirectoryResults.Analysis->ParsedExportDirectory->EATCount 
    for (uint32_t i = 0; i < NamesTableCount; i++)
    {
        char* name = (char*)RVA_TO_VA(handler->DiskPEImage->DiskImageBase, TempAddressOfNames[i]);

        if (name && name[0] != '\0')
        {
            uint32_t ordinal = TempAddressOfNameOrdinals[i];

            if(ordinal < base_ordinal) {
                continue;
            }

            uint32_t EATindex = ordinal - base_ordinal;

            if (EATindex >= EATCount)
            {
               fprintf(stderr, "[*] Warning: EAT index out of bounds, skipping...\n");
               continue;
            }

            else if (TempEAT[EATindex] == 0x0)
            {
                fprintf(stderr, "[*] Warning: Empty EAT entry, skipping...\n");
                continue;
            }

            //-----------Thats How you would call The function "DWORD GetTickCount()" from 'kernel32.dll' using Export Table----------//
            //                                                                                                                        //
            // if (strcmp(name, "GetTickCount") == 0)                                                                                 //
            // {                                                                                                                      //
            //     DWORD (*GetTickCount)(void) = (DWORD(*)(void))((uint8_t*)handler->DiskPEImage->DiskImageBase + TempEAT[EATindex]); //
            //       ^           ^         ^                                                                                          //
            //       |           |         |                                                                                          //
            //  (Return Type) (Name) (no Arguments)                                                                                   //
            //                                                                                                                        //
            //     GetTickCount();                                                                                                    //
            // }                                                                                                                      //
            //                                                                                                                        //
            //------------------------------------------------------------------------------------------------------------------------//

        }
    }

    PE_PARSED_EXPORT_DIRECTORY TempParsedExportDirectory = {
        .EAT                   = TempEAT,
        .EATCount              = EATCount,
        .AddressOfNames        = TempAddressOfNames,
        .NumberOfNames         = NamesTableCount,
        .OrdinalsBase          = base_ordinal,
        .AddressOfNameOrdinals = TempAddressOfNameOrdinals
    };
    
    ANALYSIS_CONTEXT* pTempAnalysisExportResult = calloc(1, sizeof(ANALYSIS_CONTEXT));
    if (!pTempAnalysisExportResult) 
    {
        return ERROR_RESULT;
    }

    // Allocate inner ParsedExportDirectory
    pTempAnalysisExportResult->ParsedExportDirectory = calloc(1, sizeof(PE_PARSED_EXPORT_DIRECTORY)); // free in main()
    if (!pTempAnalysisExportResult->ParsedExportDirectory) 
    {
        return ERROR_RESULT;
    }

    *pTempAnalysisExportResult->ParsedExportDirectory = TempParsedExportDirectory;
    return pTempAnalysisExportResult;
}
