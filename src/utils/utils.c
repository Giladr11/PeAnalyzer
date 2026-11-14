#include "include/internals.h"
#include <stdlib.h> 


//========================================================Helpers-Methods======================================================

// Ensures header does not exceed disk image boundaries
int IsValidRange(size_t DiskImageSize, uint32_t offset, uint32_t size)
{
    return offset + size <= DiskImageSize;
}

uint32_t RvaToOffset(uint32_t rva, MY_IMAGE_SECTION_HEADER* sections, uint16_t numSections)
{
    for (int i = 0; i < numSections; i++)
    {
        uint32_t start = sections[i].VirtualAddress;

        uint32_t size = sections[i].Misc.VirtualSize;
        if (size < sections[i].SizeOfRawData)
            size = sections[i].SizeOfRawData;

        uint32_t end = start + size;

        if (rva >= start && rva < end)
        {
            return (rva - start) + sections[i].PointerToRawData;
        }
    }

    return 0;
}

// Free Helpers
void FreeAnalysis(ANALYSIS_CONTEXT* a) {
    if (!a) return;

    if (a->ParsedExportDirectory) {free(a->ParsedExportDirectory);}

    if (a->ParsedImportDescriptors)
    {
        for (uint32_t i = 0; i < a->ImportDescsCount; i++)
        {
            free(a->ParsedImportDescriptors[i].Functions);
        }

        free(a->ParsedImportDescriptors);
        a->ParsedImportDescriptors = NULL;
    }
    
    free(a);
}

void FreeParsedExportDirectoryAnalysis(PE_PARSED_EXPORT_DIRECTORY* a) {
    if (!a) return;

    free(a->EAT);

    free(a);
}
