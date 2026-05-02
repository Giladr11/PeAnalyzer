#include "include/internals.h"


//============================================================Headers-Parsers============================================================

// DOS-Header Parser
int DosHeaderParser(HANDLER* handler) 
{
    if (!IsValidRange(handler->DiskPEImage->DiskImageSize, 0, sizeof(MY_IMAGE_DOS_HEADER))) 
    {
        fprintf(stderr, "[-] Error: DOS header exceeds File bounds\n");
        return ERROR_STATUS;
    }

    MY_IMAGE_DOS_HEADER* pTempDosHeader = (MY_IMAGE_DOS_HEADER*)handler->DiskPEImage->DiskImageBase;

    // Validate the 'MZ' (0x5A4D) signature to confirm this is a valid Dos Header
    if (pTempDosHeader->e_magic != MY_IMAGE_DOS_SIGNATURE) {
            fprintf(stderr, "[-] Error: Invalid Dos Header - e_magic is Incorrect: 0x%X\n", pTempDosHeader->e_magic);

            return ERROR_STATUS;
    }

    // Validate NT-Header Offset
    if (pTempDosHeader->e_lfanew == 0) {
        fprintf(stderr, "[-] Error: Invalid e_lfanew (no NT header offset)..\n");

        return ERROR_STATUS;
    }
    
    handler->PEContext->Headers = calloc(1, sizeof(PE_HEADERS_CONTEXT));

    // Map Dos-Header
    handler->PEContext->Headers->DosHeader = pTempDosHeader;
    
    return SUCCESS_STATUS;
}


// Extract DOS-Stub Header 
int ExtractDosStub(HANDLER* handler) 
{
    uint8_t* stub_start = (uint8_t*)handler->DiskPEImage->DiskImageBase + sizeof(MY_IMAGE_DOS_HEADER);
    uint8_t* stub_end = RVA_TO_VA(handler->DiskPEImage->DiskImageBase, handler->PEContext->Headers->DosHeader->e_lfanew);

    const char* target = "This program cannot be run in DOS mode.";
    size_t target_size = strlen(target);

    int8_t* found = NULL;

    for (uint8_t* p = stub_start; p < stub_end - target_size; p++)
    {
        if (memcmp(p, target, target_size) == 0)
        {
            found = p;
            break;
        }
    }
    
    if (memcmp(found, target, target_size) == 0)
    {
        printf("\n[+] Successfully Extracted Dos-Stub! :) \n\n");
        printf("DOS STUB: %s\n\n", found);
    }
    
    else {
        printf("\n[-] Error: Failed to Extract DOS-Stub :( \n\n");
        return ERROR_STATUS;
    }

    return SUCCESS_STATUS;
}


// NT-Headers Parser
int NTHeadersParser(HANDLER* handler)
{
    uint32_t nt_offset = handler->PEContext->Headers->DosHeader->e_lfanew;

    // Verify the NT Headers offset and size fit within the actual file buffer to prevent out-of-bounds memory access
    if (!IsValidRange(handler->DiskPEImage->DiskImageSize, nt_offset, sizeof(MY_IMAGE_NT_HEADERS64)))
    {
        fprintf(stderr, "[-] Error: NT Headers exceed File Bounds\n");
        return ERROR_STATUS;
    }

    MY_IMAGE_NT_HEADERS64* pTempNTHeaders = (MY_IMAGE_NT_HEADERS64*)(RVA_TO_VA(handler->DiskPEImage->DiskImageBase, nt_offset));

    // Validate the 'PE\0\0' (0x50450000) signature to confirm this is a valid PE file
    if (pTempNTHeaders->Signature != MY_IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "[-] Error: Invalid PE signature\n");
        return ERROR_STATUS; 
    }
    
    // File Header Parsing
    if (FileHeaderParser(&pTempNTHeaders->FileHeader) == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: File Header analysis Failed\n");
        
        return ERROR_STATUS;
    }

    // Map File Header
    handler->PEContext->Headers->FileHeader = &pTempNTHeaders->FileHeader;

    // Map NT Headers
    handler->PEContext->Headers->NtHeaders = pTempNTHeaders;

    // Optional Header Parsing call is done outside NT Header parser
    handler->PEContext->Headers->OptionalHeader = &pTempNTHeaders->OptionalHeader;

    return SUCCESS_STATUS;
}


// File-Header Parser *(Inside NT Headers)* 
int FileHeaderParser(MY_IMAGE_FILE_HEADER* pFileHeader)
{   
    // Validate section count: Windows loader standard limit is 96 sections to prevent malformed file overhead
    if (pFileHeader->NumberOfSections < 1 || pFileHeader->NumberOfSections > 96)
    {
        fprintf(stderr, "[-] Error: Invalid NumberOfSections (1 <-> 96): %hu\n", pFileHeader->NumberOfSections);

        return ERROR_STATUS;
    }

    // Ensure Optional Header size is non-zero to correctly calculate the offset of the Section Table
    if (!pFileHeader->SizeOfOptionalHeader)
    {
        fprintf(stderr, "[!] Critical: SizeOfOptionalHeader is 0. Cannot locate Section Table.\n");

        return ERROR_STATUS;
    }
    
    fprintf(stdout, "[+] File Header Parsing completed Successfully!\n");

    return SUCCESS_STATUS;
}


// Optional Header Parser Caller
int OptionalHeaderInitializer(HANDLER* handler)
{
    // Optional Header Parsing
    int32_t nt_offset = handler->PEContext->Headers->DosHeader->e_lfanew;
    MY_IMAGE_NT_HEADERS64* pTempNTHeaders = (MY_IMAGE_NT_HEADERS64*)(RVA_TO_VA(handler->DiskPEImage->DiskImageBase, nt_offset));

    TABLES_ANALYSIS_RESULTS OptionalHeaderResults = OptionalHeaderParser(handler, &pTempNTHeaders->OptionalHeader);

    if (OptionalHeaderResults.status == ERROR_STATUS)
    {   
        fprintf(stderr, "[-] Error: Optional Header analysis Failed!\n");

        FreeAnalysis(OptionalHeaderResults.Analysis);
        return ERROR_STATUS;
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
}


// Optional-Header Parser *(Inside NT Headers)* 
TABLES_ANALYSIS_RESULTS OptionalHeaderParser(HANDLER* handler, MY_IMAGE_OPTIONAL_HEADER64* pTempOptionalHeader)
{
    TABLES_ANALYSIS_RESULTS ERROR_RESULT = {.status=ERROR_STATUS};

    // Validate PE 64-bit pTempOptionalHeader Magic 
    if (pTempOptionalHeader->Magic != MY_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        fprintf(stderr, "[-] Error: Invalid Magic - Expected PE32+ (64-bit). Found 0x%X\n", pTempOptionalHeader->Magic);

        return ERROR_RESULT;
    }
    
    // Check for "Low-Alignment" mode: sections are smaller than a standard 4KB RAM page
    if (pTempOptionalHeader->SectionAlignment < PAGE_SIZE_X64)
    {
        fprintf(stderr, "[*] Warning: Low-Alignment Mode (0x%X). Permissions may be merged.\n", 
                pTempOptionalHeader->SectionAlignment);

        if (pTempOptionalHeader->SectionAlignment != pTempOptionalHeader->FileAlignment)
        {
            fprintf(stderr, "[-] Error: In Low-Alignment mode, SectionAlignment (%u) must equal "
                            "FileAlignment (%u) to prevent memory mapping corruption.\n",
                            pTempOptionalHeader->SectionAlignment, pTempOptionalHeader->FileAlignment);

            return ERROR_RESULT;
        }
    }   

    // Parse DataDirectory
    if (pTempOptionalHeader->NumberOfRvaAndSizes < MY_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        fprintf(stderr, "[*] Warning: DataDirectory has only (%u) entries (Standard is %u).\n", 
                pTempOptionalHeader->NumberOfRvaAndSizes, MY_IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    }
    
    // Store (Import & Export) RVA to Access the Tabels in the PE Image
    uint32_t ExportDirectoryRVA = pTempOptionalHeader->DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t ImportDescriptorsRVA = pTempOptionalHeader->DataDirectory[MY_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    // Initialize temps..
    MY_IMAGE_EXPORT_DIRECTORY* pTempExportDirectory = NULL;
    MY_IMAGE_IMPORT_DESCRIPTOR* pTempImportDescriptors = NULL;

    TABLES_ANALYSIS_RESULTS TempExportResults = {0};       // Export Results from ParseExportDirectory()
    TABLES_ANALYSIS_RESULTS TempImportResults = {0};       // Import Results from ParseImportDescriptors()
    TABLES_ANALYSIS_RESULTS OptionalHeaderResults = {0};  // Import & Export Final Results

    // Store (Import & Export) Table temps
    if (ExportDirectoryRVA) 
    {
        //fprintf(stdout, "[DEBUG] base image is at: %p\n", pTempOptionalHeader->ImageBase);
        //fprintf(stdout, "[DEBUG] Export Directories RVA: 0x%X\n", ExportDirectoryRVA);

        uint32_t offset = RvaToOffset(
            ExportDirectoryRVA,
            handler->PEContext->Headers->SectionHeaders,
            handler->PEContext->Headers->FileHeader->NumberOfSections
        );

        if (offset == UINT32_MAX)
        {
            fprintf(stderr, "[-] Invalid RVA\n");
            return ERROR_RESULT;
        }

        pTempExportDirectory = (MY_IMAGE_EXPORT_DIRECTORY*)(handler->DiskPEImage->DiskImageBase + offset);

        //fprintf(stderr,
        //    "[DEBUG] Export Directories (file ptr): %p | RVA: 0x%X\n",
        //    pTempExportDirectory,
        //    ExportDirectoryRVA);
            
    }
    else
    {
        fprintf(stderr, "[*] Warning: No Export Directory found (Export RVA = %u)\n", ExportDirectoryRVA);
    }

    if (ImportDescriptorsRVA) 
    {
        //fprintf(stdout, "[DEBUG] base image is at: %p\n", pTempOptionalHeader->ImageBase);
        //fprintf(stdout, "[DEBUG] Import Descriptors RVA: 0x%X\n", ImportDescriptorsRVA);

        uint32_t offset = RvaToOffset(
            ImportDescriptorsRVA,
            handler->PEContext->Headers->SectionHeaders,
            handler->PEContext->Headers->FileHeader->NumberOfSections
        );

        if (offset == UINT32_MAX)
        {
            fprintf(stderr, "[-] Invalid RVA\n");
            return ERROR_RESULT;
        }

        pTempImportDescriptors = (MY_IMAGE_IMPORT_DESCRIPTOR*)(handler->DiskPEImage->DiskImageBase + offset);

        //fprintf(stderr,
        //    "[DEBUG] Import Descriptors (file ptr): %p | RVA: 0x%X\n",
        //    pTempImportDescriptors,
        //    ImportDescriptorsRVA);
    }
    
    else
    {
        fprintf(stdout, "[*] Warning: No Import Descriptors found (Import RVA = %u)\n", ImportDescriptorsRVA);
    }
    
    // Execute (Export Directory) Parser 
    if (pTempExportDirectory) 
    {
        TempExportResults = ExportDirectoryParser(handler, pTempExportDirectory);

        if (TempExportResults.status == SUCCESS_STATUS)
        {
            fprintf(stdout, "[+] Export Directories parsing completed Successfully!\n");

            OptionalHeaderResults.ExportDirectory = pTempExportDirectory;
        }
        else
        {
            fprintf(stderr, "[-] Error: Failed to analyze Export Table\n");
        }
    }

    if (TempExportResults.status == ERROR_STATUS)
    {
        fprintf(stderr, "[-] Error: Failed to analyze Export Table\n");
    }  
    
    // Proceed To Execute (Import Table) Parser *(After Export Table Parser Succeeded)*
    if (pTempImportDescriptors) 
    {
        TempImportResults = ImportDescriptorsParser(handler, pTempImportDescriptors);

        if (TempImportResults.status == SUCCESS_STATUS)
        {
            fprintf(stdout, "[+] Import Descriptors parsing completed Successfully!\n");

            OptionalHeaderResults.ImportDescriptors = pTempImportDescriptors;
        }
        else
        {
            fprintf(stderr, "[-] Error: Failed to analyze Import Table\n");
        }
    }

    OptionalHeaderResults.Analysis = calloc(1, sizeof(ANALYSIS_CONTEXT));

    if (!OptionalHeaderResults.Analysis)
    {
        fprintf(stderr, "[-] Error: calloc failed\n");
        return ERROR_RESULT;
    }
    
    if (TempExportResults.status == SUCCESS_STATUS && TempExportResults.Analysis)
    {
        // Transfer ownership
        OptionalHeaderResults.Analysis->ParsedExportDirectory = TempExportResults.Analysis->ParsedExportDirectory;

        // Detach double pointer to memory
        TempExportResults.Analysis->ParsedExportDirectory = NULL; 

        // Free temporary container (no longer owns any heap data)
        free(TempExportResults.Analysis);
    }

    if (TempImportResults.status == SUCCESS_STATUS && TempImportResults.Analysis)
    {   
        // Transfer ownership
        OptionalHeaderResults.Analysis->ParsedImportDescriptors = TempImportResults.Analysis->ParsedImportDescriptors; // Makes it point to the same memory address TempImportResults.Analysis->ParsedImportDescriptors points to..

        // Detach double pointer to memory
        TempImportResults.Analysis->ParsedImportDescriptors = NULL;

        // Free temporary container (no longer owns any heap data)
        free(TempImportResults.Analysis);
    }

    return OptionalHeaderResults;
}
