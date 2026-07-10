#include "../include/internals.h"

//============================================================Sections-Dumper============================================================

STATUS DumpSectionHeader(MY_IMAGE_SECTION_HEADER* sections_header, uint16_t NumberOfSections)
{
    printf("\n=====================Sections-Header-Dumping=======================\n");

    MY_IMAGE_SECTION_HEADER* tmp_sections_header = sections_header;
    for (size_t i = 0; i < NumberOfSections; i++)
    {
        printf("\nSection Number: %zu\n", i);

        printf("Name: %.8s\n", tmp_sections_header->Name);

        printf("VirtualSize:       0x%08X\n", tmp_sections_header->Misc.VirtualSize);
        printf("PhysicalAddress:   0x%08X\n", tmp_sections_header->Misc.PhysicalAddress);
        
        printf("VirtualAddress:    0x%08X\n", tmp_sections_header->VirtualAddress);
        printf("SizeOfRawData:     0x%08X\n", tmp_sections_header->SizeOfRawData);
        printf("PointerToRawData:  0x%08X\n", tmp_sections_header->PointerToRawData);
        
        printf("PointerToRelocations: 0x%08X\n", tmp_sections_header->PointerToRelocations);
        printf("PointerToLinenumbers: 0x%08X\n", tmp_sections_header->PointerToLinenumbers);
        
        printf("NumberOfRelocations:  %u\n", tmp_sections_header->NumberOfRelocations);
        printf("NumberOfLinenumbers:  %u\n", tmp_sections_header->NumberOfLinenumbers);
        
        printf("Characteristics:   0x%08X\n", tmp_sections_header->Characteristics);

        tmp_sections_header++;
    }

    return SUCCESS_STATUS;
}
