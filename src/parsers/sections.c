#include "include/internals.h"


//============================================================Sections-Parsers============================================================

int SectionHeadersParser(HANDLER* handler)
{
    if (!handler || !handler->DiskPEImage || !handler->DiskPEImage->DiskImageBase)
    {
        fprintf(stderr, "[-] Error: Invalid HANDLER or DiskImageBase is NULL\n");
        return STATUS_ERROR;
    }

    uint16_t NumberOfSections = handler->PEContext->Headers->FileHeader->NumberOfSections;

    fprintf(stdout, "[DEBUG] Number of Sections: %hu\n", NumberOfSections);

    if (NumberOfSections == 0 || NumberOfSections > 96)
    {
        fprintf(stderr, "[-] Error: Invalid NumberOfSections: %hu\n", NumberOfSections);
        return STATUS_ERROR;
    }

    // Iterate over sections
    uint8_t* base = handler->DiskPEImage->DiskImageBase;

    MY_IMAGE_DOS_HEADER* dos = (MY_IMAGE_DOS_HEADER*)base;
    MY_IMAGE_NT_HEADERS64* nt = (MY_IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    MY_IMAGE_SECTION_HEADER* pTempSectionHeader = 
        (MY_IMAGE_SECTION_HEADER*)
        ((uint8_t*)&nt->OptionalHeader + 
         nt->FileHeader.SizeOfOptionalHeader);
    
    uint8_t* sectionEnd = (uint8_t*)pTempSectionHeader + (NumberOfSections * sizeof(MY_IMAGE_SECTION_HEADER));

    if (sectionEnd > base + handler->DiskPEImage->DiskImageSize)
    {
        fprintf(stderr, "[-] Error: Section headers exceed file bounds\n");
        return STATUS_ERROR;
    }

    handler->PEContext->Headers->SectionHeaders = calloc(NumberOfSections, sizeof(MY_IMAGE_SECTION_HEADER));
    if (!handler->PEContext->Headers->SectionHeaders)
    {
        fprintf(stderr, "[-] Error: Failed to allocate SectionHeaders\n");
        return STATUS_ERROR;
    }

    for (uint16_t i = 0; i < NumberOfSections; i++)
    {   
        if (pTempSectionHeader[i].Name[0] == 0 && pTempSectionHeader[i].Name[1] == 0)
        {
            fprintf(stderr, "[-] Error: Empty section name at index %u\n", i);
            return STATUS_ERROR;
        }

        if (pTempSectionHeader[i].SizeOfRawData > 0x10000000)
        {
            fprintf(stderr, "[-] Error: Section %u too large (SizeOfRawData)\n", i);
            return STATUS_ERROR;
        }

        if (pTempSectionHeader[i].Misc.VirtualSize == 0 && pTempSectionHeader[i].SizeOfRawData == 0)
        {
            fprintf(stderr, "[-] Error: Section %u has zero size\n", i);
            return STATUS_ERROR;
        }

        if (pTempSectionHeader[i].PointerToRawData > handler->DiskPEImage->DiskImageSize)
        {
            fprintf(stderr, "[-] Error: Section %u raw pointer out of bounds\n", i);
            return STATUS_ERROR;
        }

        if ((pTempSectionHeader[i].PointerToRawData + pTempSectionHeader[i].SizeOfRawData) > (handler->DiskPEImage->DiskImageSize - pTempSectionHeader[i].SizeOfRawData))
        {
            fprintf(stderr, "[-] Error: Section %u exceeds file size\n", i);
            return STATUS_ERROR;
        }

        handler->PEContext->Headers->SectionHeaders[i] = pTempSectionHeader[i];
        printf("[DEBUG] Section NAME: %s\n", pTempSectionHeader[i].Name);
    }

    return STATUS_SUCCESS;
}
