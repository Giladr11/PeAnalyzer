#include "../include/internals.h"
#include "../include/pe_headers.h"

//============================================================NT-Headers-Dumping============================================================

STATUS DumpFileHeader(MY_IMAGE_FILE_HEADER* file_header)
{
    printf("Machine:                   0x%04X\n", file_header->Machine);
    printf("NumberOfSections:          0x%04X\n", file_header->NumberOfSections);
    printf("TimeDateStamp:             0x%08X\n", file_header->TimeDateStamp);
    printf("PointerToSymbolTable:      0x%08X\n", file_header->PointerToSymbolTable);
    printf("NumberOfSymbols:           0x%08X\n", file_header->NumberOfSymbols);
    printf("SizeOfOptionalHeader:      0x%04X\n", file_header->SizeOfOptionalHeader);
    printf("Characteristics:           0x%04X\n", file_header->Characteristics);

    return SUCCESS_STATUS;
}

STATUS DumpOptionalHeader(MY_IMAGE_OPTIONAL_HEADER64* optional_header)
{
    printf("Magic:                        0x%04X\n", optional_header->Magic);
    printf("MajorLinkerVersion:           0x%02X\n", optional_header->MajorLinkerVersion);
    printf("MinorLinkerVersion:           0x%02X\n", optional_header->MinorLinkerVersion);
    printf("SizeOfCode:                   0x%08X\n", optional_header->SizeOfCode);
    printf("SizeOfInitializedData:        0x%08X\n", optional_header->SizeOfInitializedData);
    printf("SizeOfUninitializedData:      0x%08X\n", optional_header->SizeOfUninitializedData);
    printf("AddressOfEntryPoint:          0x%08X\n", optional_header->AddressOfEntryPoint);
    printf("BaseOfCode:                   0x%08X\n", optional_header->BaseOfCode);
    printf("ImageBase:                    0x%016llX\n", optional_header->ImageBase);
    printf("SectionAlignment:             0x%08X\n", optional_header->SectionAlignment);
    printf("FileAlignment:                0x%08X\n", optional_header->FileAlignment);
    printf("MajorOperatingSystemVersion:  0x%04X\n", optional_header->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion:  0x%04X\n", optional_header->MinorOperatingSystemVersion);
    printf("MajorImageVersion:            0x%04X\n", optional_header->MajorImageVersion);
    printf("MinorImageVersion:            0x%04X\n", optional_header->MinorImageVersion);
    printf("MajorSubsystemVersion:        0x%04X\n", optional_header->MajorSubsystemVersion);
    printf("MinorSubsystemVersion:        0x%04X\n", optional_header->MinorSubsystemVersion);
    printf("Win32VersionValue:            0x%08X\n", optional_header->Win32VersionValue);
    printf("SizeOfImage:                  0x%08X\n", optional_header->SizeOfImage);
    printf("SizeOfHeaders:                0x%08X\n", optional_header->SizeOfHeaders);
    printf("CheckSum:                     0x%08X\n", optional_header->CheckSum);
    printf("SubSystem:                    0x%04X\n", optional_header->Subsystem);
    printf("DllCharacteristics:           0x%04X\n", optional_header->DllCharacteristics);
    printf("SizeOfStackReserve:           0x%016llX\n", optional_header->SizeOfStackReserve);
    printf("SizeOfStackStackCommit:       0x%016llX\n", optional_header->SizeOfStackCommit);
    printf("SizeOfHeapReserve:            0x%016llX\n", optional_header->SizeOfHeapReserve);
    printf("SizeOfHeapCommit:             0x%016llX\n", optional_header->SizeOfHeapCommit);
    printf("LoaderFlags:                  0x%08X\n", optional_header->LoaderFlags);
    printf("NumberOfRvaAndSizes:          0x%08X\n", optional_header->NumberOfRvaAndSizes);
    
    return SUCCESS_STATUS;
}