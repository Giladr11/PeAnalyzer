#include "include/internals.h"

#define MAX_IMPORT_DESCRIPTORS 4096


//========================================================Imports-Parsers========================================================

static uint32_t GetImportDescriptorsCount(
    MY_IMAGE_IMPORT_DESCRIPTOR* desc,
    uint8_t* base,
    size_t size)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < MAX_IMPORT_DESCRIPTORS; i++)
    {
        MY_IMAGE_IMPORT_DESCRIPTOR* cur = &desc[i];

        // validate descriptor memory range
        if ((uint8_t*)cur < base ||
            (uint8_t*)cur + sizeof(MY_IMAGE_IMPORT_DESCRIPTOR) > base + size)
        {
            break;
        }

        // null terminator descriptor
        if (cur->Name == 0 &&
            cur->FirstThunk == 0 &&
            cur->OriginalFirstThunk == 0)
        {
            break;
        }

        count++;
    }

    return count;
}


// Import Descriptors Parser *(INT/IAT per DLL)* 
TABLES_ANALYSIS_RESULTS ImportDescriptorsParser(HANDLER* handler, MY_IMAGE_IMPORT_DESCRIPTOR* pTempImportDescriptors)
{
    TABLES_ANALYSIS_RESULTS ERROR_RESULT = {.status=ERROR_STATUS};
    
    ANALYSIS_CONTEXT* pTempAnalysisImportResult = calloc(1, sizeof(ANALYSIS_CONTEXT));
    if (!pTempAnalysisImportResult) 
    {
        fprintf(stderr, "[-] ImportDescriptorsParser: pTempAnalysisImportResult is NULL\n");
        return ERROR_RESULT;
    }

    uint32_t TempImportDescsCount = GetImportDescriptorsCount(
                                    pTempImportDescriptors,
                                    handler->DiskPEImage->DiskImageBase,
                                    handler->DiskPEImage->DiskImageSize
                                );

    if (!TempImportDescsCount)
    {
        fprintf(stderr, "[-] Error: No import descriptors found\n");

        free(pTempAnalysisImportResult);
        return ERROR_RESULT;
    }
    
    // Allocate inner ParsedImportDescriptors
    pTempAnalysisImportResult->ParsedImportDescriptors = calloc(TempImportDescsCount, sizeof(PE_PARSED_IMPORT_DESCRIPTOR)); // free in main()
    if (!pTempAnalysisImportResult->ParsedImportDescriptors) 
    {
        free(pTempAnalysisImportResult);
        return ERROR_RESULT;
    }

    MY_IMAGE_THUNK_DATA64* TempINT = NULL;
    MY_IMAGE_THUNK_DATA64* TempIAT = NULL;

    uint8_t* base = handler->DiskPEImage->DiskImageBase;
    
    for (uint32_t i = 0; i < TempImportDescsCount; i++)
    {   
        uint32_t offsetset = RvaToOffset(
            pTempImportDescriptors[i].Name,
            handler->PEContext->Headers->SectionHeaders,
            handler->PEContext->Headers->FileHeader->NumberOfSections
        );
        
        uint8_t* addr = base + offsetset;

        if (!addr || addr < base || addr >= (base + handler->DiskPEImage->DiskImageSize))
        {
            fprintf(stderr, "[-] Invalid Name RVA\n");

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);
            return ERROR_RESULT;
        }

        char* dllName = (char*)addr;

        //fprintf(stderr, "[DEBUG] dll index: (%d), dll name: %s\n", i, dllName);

        if (!dllName || dllName[0] == '\0')
        {
            fprintf(stderr, "[-] Error: DLL Name Doesnt Exist..\n");

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);
            return ERROR_RESULT;
        }

        uint32_t INT_RVA = pTempImportDescriptors[i].OriginalFirstThunk;
        uint32_t IAT_RVA = pTempImportDescriptors[i].FirstThunk;

        if (IAT_RVA == 0)
        {
            fprintf(stderr, "[-] Invalid IAT RVA\n");
            return ERROR_RESULT;
        }

        uint32_t iat_offset = RvaToOffset(
            IAT_RVA,
            handler->PEContext->Headers->SectionHeaders,
            handler->PEContext->Headers->FileHeader->NumberOfSections
        );

        if (iat_offset >= handler->DiskPEImage->DiskImageSize)
        {
            fprintf(stderr, "[-] Invalid IAT offsetset\n");
            return ERROR_RESULT;
        }

        TempIAT = (MY_IMAGE_THUNK_DATA64*)(base + iat_offset);

        if (INT_RVA == 0)
        {
            // fallback
            TempINT = TempIAT;
        }
        else
        {
            uint32_t int_offset = RvaToOffset(
                INT_RVA,
                handler->PEContext->Headers->SectionHeaders,
                handler->PEContext->Headers->FileHeader->NumberOfSections
            );
        
            if (int_offset >= handler->DiskPEImage->DiskImageSize)
            {
                fprintf(stderr, "[-] Invalid INT offsetset\n");
                return ERROR_RESULT;
            }
        
            TempINT = (MY_IMAGE_THUNK_DATA64*)(base + int_offset);
        }

        PE_PARSED_IMPORT_DESCRIPTOR* pDesc = &pTempAnalysisImportResult->ParsedImportDescriptors[i];

        pDesc->DllName = dllName;
        pDesc->INT = TempINT;
        pDesc->IAT = TempIAT;
        pDesc->Functions = NULL;
        pDesc->FunctionsCount = 0;

        STATUS status = ThunkTablesParser(handler, pDesc);

        if (status == ERROR_STATUS) 
        {
            fprintf(stderr, "[-] Error: Failed to parse Thunk Tables for: %s\n", dllName);
        }
    }

    return (TABLES_ANALYSIS_RESULTS){
        .ImportDescsCount  = TempImportDescsCount,
        .Analysis          = pTempAnalysisImportResult,
        .status            = SUCCESS_STATUS
    };
}

// Generic (INT & IAT) Parser
STATUS ThunkTablesParser(HANDLER* handler, PE_PARSED_IMPORT_DESCRIPTOR* pTempParsedImportDescriptor)
{
    if (!pTempParsedImportDescriptor)
    {
        fprintf(stderr, "[-] Error: pTempParsedImportDescriptor is NULL\n");
        
        return ERROR_STATUS;
    }

    if (!pTempParsedImportDescriptor->INT)
    {
        fprintf(stderr, "[-] Error: INT pointer: %p is NULL (FirstThunk missing)\n",
            pTempParsedImportDescriptor->INT);
            
        return ERROR_STATUS;
    }

    if (!pTempParsedImportDescriptor->IAT)
    {
        fprintf(stderr, "[-] Error: IAT pointer: %p is NULL (FirstThunk missing)\n",
            pTempParsedImportDescriptor->IAT);

        return ERROR_STATUS;
    }

    MY_IMAGE_THUNK_DATA64* INTthunks = pTempParsedImportDescriptor->INT;
    MY_IMAGE_THUNK_DATA64* IATthunks = pTempParsedImportDescriptor->IAT;

    MY_IMAGE_IMPORT_BY_NAME* INTentry = NULL;

    uint64_t ordinalFlag = 1ULL << 63; // shift left 63 bits to get 0b1..{0*63}

    // Calculate Number of functions in DLL
    uint32_t count = 0;
    while (INTthunks[count].u1.AddressOfData != 0) 
    {
        count++;

        // Safety guard
        if (count > 100000) break;
    }
    pTempParsedImportDescriptor->FunctionsCount = count;
    
    // Allocate Functions Array
    pTempParsedImportDescriptor->Functions = calloc(count, sizeof(PE_PARSED_IMPORT_FUNCTION)); // free in main()
    if (!pTempParsedImportDescriptor->Functions)
    {
        fprintf(stderr, "[-] Error: Failed to allocate Functions array\n");

        return ERROR_STATUS;
    }

    // Reduces Memory Access Overhead
    PE_PARSED_IMPORT_FUNCTION* pTempFunctions = pTempParsedImportDescriptor->Functions;
    
    // Iterate Over Imported DLL Functions
    for (uint32_t i = 0; i < count; i++)
    {
        uint64_t value = INTthunks[i].u1.AddressOfData;

        //fprintf(stderr,
        //    "\n[DEBUG] ==== THUNK %u ====\n"
        //    "[DEBUG] INT thunk ptr      : %p\n"
        //    "[DEBUG] raw thunk value    : 0x%016llX\n",
        //    i,
        //    &INTthunks[i],
        //    (unsigned long long)value
        //);

        // ordinal import
        if (value & ordinalFlag)
        {
            uint16_t ordinal = (uint16_t)(value & 0xFFFF);

            //fprintf(stderr,
            //    "[DEBUG] ordinal import detected\n"
            //    "[DEBUG] ordinal = %hu\n",
            //    ordinal
            //);

            pTempFunctions[i].IsOrdinal = 1;
            pTempFunctions[i].Ordinal = ordinal;
            pTempFunctions[i].FunctionName = NULL;

            //fprintf(stdout,
            //    "[+] Importing DLL Function Using ordinal: %hu\n",
            //    ordinal
            //);
        }
        else
        {
            uint32_t nameRva = (uint32_t)value;

            //fprintf(stderr,
            //    "[DEBUG] import-by-name\n"
            //    "[DEBUG] Name RVA = 0x%08X\n",
            //    nameRva
            //);

            uint32_t offset = RvaToOffset(
                nameRva,
                handler->PEContext->Headers->SectionHeaders,
                handler->PEContext->Headers->FileHeader->NumberOfSections
            );

            //fprintf(stderr,
            //    "[DEBUG] file offsetset = 0x%08X\n",
            //    offset
            //);

            if (offset == 0 || offset >= handler->DiskPEImage->DiskImageSize)
            {
                fprintf(stderr,
                    "[-] Invalid INT RVA\n"
                    "[-] RVA  = 0x%08X\n"
                    "[-] offset  = 0x%08X\n"
                    "[-] SIZE = 0x%llX\n",
                    nameRva,
                    offset,
                    (unsigned long long)handler->DiskPEImage->DiskImageSize
                );
                return ERROR_STATUS;
            }

            INTentry = (MY_IMAGE_IMPORT_BY_NAME*)
                (handler->DiskPEImage->DiskImageBase + offset);

            //fprintf(stderr,
            //    "[DEBUG] INTentry ptr = %p\n"
            //    "[DEBUG] hint         = 0x%04X\n"
            //    "[DEBUG] name ptr     = %p\n"
            //    "[DEBUG] name         = %s\n",
            //    INTentry,
            //    INTentry->hint,
            //    INTentry->Name,
            //    INTentry->Name
            //);

            if (!INTentry)
            {
                fprintf(stderr, "[-] Invalid INT entry at index %u\n", i);
                return ERROR_STATUS;
            }

            pTempFunctions[i].IsOrdinal = 0;
            pTempFunctions[i].Ordinal = 0;
            pTempFunctions[i].FunctionName = INTentry->Name;

            //fprintf(stdout,
            //    "[+] Importing DLL Function Using a Name: %s\n",
            //    pTempFunctions[i].FunctionName
            //);
        }

        uint64_t IATFunction = IATthunks[i].u1.Function;
        pTempFunctions[i].IATAddress = IATFunction;

        //fprintf(stderr,
        //    "[DEBUG] IAT thunk ptr      : %p\n"
        //    "[DEBUG] IAT function value : 0x%016llX\n",
        //    &IATthunks[i],
        //    (unsigned long long)IATFunction
        //);

        if (!IATFunction)
        {
            fprintf(stderr, "[*] Warning: Unresolved IAT entry at index: %u\n", i);
        }
    }

    return SUCCESS_STATUS;
}
