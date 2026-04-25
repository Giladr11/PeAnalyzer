#include "include/internals.h"

#define MAX_IMPORT_DESCRIPTORS 4096


//============================================================Imports-Parsers============================================================

static uint32_t GetImportDescriptorsCount(MY_IMAGE_IMPORT_DESCRIPTOR* desc, uint8_t* base, size_t size)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < MAX_IMPORT_DESCRIPTORS; i++)
    {
        if (!desc)
            break;

        // validate descriptor memory range
        if ((uint8_t*)desc < base ||
            (uint8_t*)desc + sizeof(MY_IMAGE_IMPORT_DESCRIPTOR) > base + size)
        {
            break;
        }

        if (desc->Name == 0 &&
            desc->FirstThunk == 0 &&
            desc->OriginalFirstThunk == 0)
        {
            break;
        }

        count++;
        desc++;
    }

    return count;
}

void* RVA_TO_RAW(HANDLER* handler, uint32_t rva)
{
    uint8_t* base = handler->DiskPEImage->DiskImageBase;

    MY_IMAGE_DOS_HEADER* dos = (MY_IMAGE_DOS_HEADER*)base;
    MY_IMAGE_NT_HEADERS64* nt =
        (MY_IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    MY_IMAGE_SECTION_HEADER* sec =
        (MY_IMAGE_SECTION_HEADER*)
        ((uint8_t*)&nt->OptionalHeader +
         nt->FileHeader.SizeOfOptionalHeader);

    uint16_t n = nt->FileHeader.NumberOfSections;

    for (uint16_t i = 0; i < n; i++)
    {
        uint32_t va   = sec[i].VirtualAddress;
        uint32_t size = sec[i].Misc.VirtualSize;
        uint32_t raw  = sec[i].PointerToRawData;

        if (rva >= va && rva < va + size)
        {
            uint32_t offset = raw + (rva - va);
            return base + offset;
        }
    }

    return NULL;
}

// Import Descriptors Parser *(INT/IAT per DLL)* 
TABLES_ANALYSIS_RESULTS ImportDescriptorsParser(HANDLER* handler, MY_IMAGE_IMPORT_DESCRIPTOR* pTempImportDescriptors)
{
    TABLES_ANALYSIS_RESULTS ERROR_RESULT = {.status=STATUS_ERROR};
    
    ANALYSIS_CONTEXT* pTempAnalysisImportResult = calloc(1, sizeof(ANALYSIS_CONTEXT));
    if (!pTempAnalysisImportResult) 
    {
        fprintf(stderr, "[-] ImportDescriptorsParser: pTempAnalysisImportResult is NULL\n");
        return ERROR_RESULT;
    }

    // Calculate Number of Import Descriptors
    MY_IMAGE_IMPORT_DESCRIPTOR* pImportdescriptors = pTempImportDescriptors;
    if (!pImportdescriptors)
    {
        fprintf(stderr, "[-] ImportDescriptorsParser: pTempImportDescriptors is NULL\n");

        free(pTempAnalysisImportResult);
        return ERROR_RESULT;
    }

    uint32_t TempImportDescsCount = GetImportDescriptorsCount(
                                        pImportdescriptors,
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
        uint8_t* addr = RVA_TO_RAW(handler, pImportdescriptors->Name);

        if (!addr || addr < base || addr >= base + handler->DiskPEImage->DiskImageSize)
        {
            fprintf(stderr, "[-] Invalid Name RVA\n");

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);
            return ERROR_RESULT;
        }

        char* dllName = (char*)RVA_TO_RAW(handler, pImportdescriptors->Name);

        if (!dllName || dllName[0] == '\0')
        {
            fprintf(stderr, "[-] Error: DLL Name Doesnt Exist..\n");

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);
            return ERROR_RESULT;
        }

        // Map INT & IAT 
        uint32_t INT_RVA = pImportdescriptors->OriginalFirstThunk;
        uint32_t IAT_RVA = pImportdescriptors->FirstThunk;

        if (pImportdescriptors->FirstThunk == 0)
        {
            fprintf(stderr, "[-] Error: Invalid IAT RVA..\n");

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);
            return ERROR_RESULT;
        }

        TempIAT = (MY_IMAGE_THUNK_DATA64*)RVA_TO_RAW(handler, IAT_RVA);

        if (INT_RVA)
        {
            TempINT = (MY_IMAGE_THUNK_DATA64*)RVA_TO_RAW(handler, INT_RVA);
        }    
        else {
            fprintf(stderr, "[*] Warning: Missing INT, using IAT as fallback..\n");

            TempINT = TempIAT;
        }

        // Initialize Results
        PE_PARSED_IMPORT_DESCRIPTOR pTempParsedImportDescriptor = {
            .DllName = dllName,
            .INT = TempINT,
            .IAT = TempIAT,
            .Functions = NULL,
            .FunctionsCount = 0
        };

        // Parse INT & IAT for A DLL
        STATUS status = ThunkTablesParser(handler, &pTempParsedImportDescriptor);

        if (status == STATUS_ERROR)
        {
            fprintf(stderr, "[-] Error: Failed to Parse (IAT/INT) for DLL: %s\n", dllName);

            if(pTempParsedImportDescriptor.Functions)
            {
                free(pTempParsedImportDescriptor.Functions);
            }

            free(pTempAnalysisImportResult->ParsedImportDescriptors);
            free(pTempAnalysisImportResult);

            return ERROR_RESULT;
        }

        pTempAnalysisImportResult->ParsedImportDescriptors[i] = pTempParsedImportDescriptor;
        
        // Move to the next Import Descriptor in memory..
        pImportdescriptors++;
    }
    
    fprintf(stdout, "[+] Import Descriptors parsing completed Successfully\n");

    return (TABLES_ANALYSIS_RESULTS){
        .ImportDescsCount  = TempImportDescsCount,
        .Analysis          = pTempAnalysisImportResult,
        .status            = STATUS_SUCCESS
    };
}

// Generic (INT & IAT) Parser
STATUS ThunkTablesParser(HANDLER* handler, PE_PARSED_IMPORT_DESCRIPTOR* pTempParsedImportDescriptor)
{
    if (!pTempParsedImportDescriptor)
    {
        fprintf(stderr,
            "[-] Error: pTempParsedImportDescriptor is NULL\n");
        
        return STATUS_ERROR;
    }

    if (!pTempParsedImportDescriptor->INT)
    {
        fprintf(stderr,
            "[-] Error: INT pointer: %p is NULL (FirstThunk missing)\n",
            pTempParsedImportDescriptor->INT);
            
        return STATUS_ERROR;
    }

    if (!pTempParsedImportDescriptor->IAT)
    {
        fprintf(stderr,
            "[-] Error: IAT pointer: %p is NULL (FirstThunk missing)\n",
            pTempParsedImportDescriptor->IAT);

        return STATUS_ERROR;
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

        return STATUS_ERROR;
    }

    // Reduces Memory Access Overhead
    PE_PARSED_IMPORT_FUNCTION* pTempFunctions = pTempParsedImportDescriptor->Functions;
    
    // Iterate Over Imported DLL Functions
    for (uint32_t i = 0; i < count; i++)
    {
        uint64_t value = INTthunks[i].u1.AddressOfData;

        // MSB set → ordinal import (not import-by-name struct)
        if (value & ordinalFlag)
        {
            uint16_t ordinal = (uint16_t)(value & 0xFFFF);

            pTempFunctions[i].IsOrdinal = 0x01;
            pTempFunctions[i].Ordinal = ordinal;
            pTempFunctions[i].FunctionName = NULL;

            fprintf(stdout, "[+] Importing DLL Function Using an ordinal: %hu\n", ordinal);
        }
        else
        {
            INTentry = (MY_IMAGE_IMPORT_BY_NAME*)RVA_TO_RAW(handler, value);

            if (!INTentry || !INTentry->Name)
            {
                fprintf(stderr,
                    "[-] Invalid INT entry at index %u\n",
                    i);
                return STATUS_ERROR;
            }

            pTempFunctions[i].IsOrdinal = 0x00;
            pTempFunctions[i].Ordinal = 0;
            pTempFunctions[i].FunctionName = INTentry->Name;

            fprintf(stdout, "[+] Importing DLL Function Using a Name: %s\n", pTempFunctions[i].FunctionName);
        } 

        uint64_t IATFunction = IATthunks[i].u1.Function;
        pTempFunctions[i].IATAddress = IATFunction;

        // Map IAT Addresses
        if (!IATFunction)
        {
            fprintf(stderr, "[*] Warning: Unresolved IAT entry at index: %u\n", i);
        }
    }

    return STATUS_SUCCESS;
}
