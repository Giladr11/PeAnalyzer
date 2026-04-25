#include "include/internals.h"


//===================================================================Helpers-Methods===================================================================

// Extract DOS-Stub Header 
int ExtractDosStub(HANDLER* handler) 
{
    uint8_t* stub_start = (uint8_t*)handler->PEDiskImage->DiskImageBase + sizeof(MY_IMAGE_DOS_HEADER);
    uint8_t* stub_end = RVA_TO_VA(handler->PEDiskImage->DiskImageBase, handler->PEContext->Headers->DosHeader->e_lfanew);

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
    
    if (found)
    {
        printf("Extracted Dos-Stub While Analyzing DOS-HEADER! :) \n");
        printf("DOS STUB: %s\n", found);
    }
    
    else {
        printf("Couldn't Extract DOS-Stub :( \n");
        return STATUS_ERROR;
    }

    return STATUS_SUCCESS;
}

// Ensures header does not exceed disk image boundaries
int IsValidRange(size_t DiskImageSize, uint32_t offset, uint32_t size)
{
    return offset + size <= DiskImageSize;
}

// free Helpers
void FreeAnalysis(ANALYSIS_CONTEXT* a) {
    if (!a) return;

    free(a->ParsedExportDirectory);
    free(a->ParsedImportDescriptors);
    free(a);
}

void FreeParsedExportDirectoryAnalysis(PE_PARSED_EXPORT_DIRECTORY* a) {
    if (!a) return;

    free(a->EAT);

    free(a);
}
