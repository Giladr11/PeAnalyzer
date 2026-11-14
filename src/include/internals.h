// Internal Structs & API

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "pe_headers.h"


//------------------------------------Init-PE-Analyzer--------------------------------------

void* ReadPEDiskImage(char* pe_path, size_t* pe_size);
HANDLER* InitializeHandler(void* pe_base, size_t pe_size);

//------------------------------------Internal-Structs--------------------------------------

typedef struct {
    MY_IMAGE_EXPORT_DIRECTORY* ExportDirectory;        // Pointer to raw Export Directory (DataDirectory[0])
    MY_IMAGE_IMPORT_DESCRIPTOR* ImportDescriptors;     // Pointer to raw Import Descriptors array (DataDirectory[1])
    uint32_t ImportDescsCount;                         // Number of Import Descriptors

    ANALYSIS_CONTEXT* Analysis;                        // Parsed (Import/Export) Analysis results (EAT & (INT/IAT per-DLL))

    STATUS status;                                     // Parsing/validation status for export/import processing
} TABLES_ANALYSIS_RESULTS;

//--------------------------------Internal-Parsing-Routines---------------------------------

// Parse Functions *(Validate & Map (PE headers & RVAs) from 'RawImage' into a 'PEObj')*
STATUS DosHeaderParser(HANDLER* handler);

// Extract DOS Stub Header ("This program cannot be run in DOS mode.")
STATUS DosStubParser(HANDLER* handler);

STATUS NTHeadersParser(HANDLER* handler);
STATUS FileHeaderParser(MY_IMAGE_FILE_HEADER* pFileHeader);
STATUS OptionalHeaderInitializer(HANDLER* handler);
TABLES_ANALYSIS_RESULTS OptionalHeaderParser(HANDLER* handler, MY_IMAGE_OPTIONAL_HEADER64* pTempOptionalHeader);

// Exports & Imports
//---DataDirectory[1] & (EAT)-Parser---------------------

TABLES_ANALYSIS_RESULTS ExportDirectoryParser(HANDLER* handler, MY_IMAGE_EXPORT_DIRECTORY* pTempExportDirectory);      // OptionalHeader->DataDirectory[0].VirtualAddress

// EAT Parser 
ANALYSIS_CONTEXT* EATParser(HANDLER* handler, MY_IMAGE_EXPORT_DIRECTORY* pTempExportDirectory);
//-------------------------------------------------------


//---DataDirectory[1] & (IAT/INT)-Parser-----------------
TABLES_ANALYSIS_RESULTS ImportDescriptorsParser(HANDLER* handler, MY_IMAGE_IMPORT_DESCRIPTOR* pTempImportDescriptors); // OptionalHeader->DataDirectory[1].VirtualAddress        

STATUS ThunkTablesParser(HANDLER* handler, PE_PARSED_IMPORT_DESCRIPTOR* pTempParsedImportDescriptors);                 // Parse INT & IAT Per one Descriptor (one dll)
//-------------------------------------------------------

STATUS SectionHeadersParser(HANDLER* handler);

//----------------------------Internal-Context-Dumping----------------------------------

// Context Dumping
STATUS DumpDosHeader(MY_IMAGE_DOS_HEADER* dos_header);
STATUS DumpDosStub(char* dos_stub);
STATUS DumpNTHeaders(PE_CONTEXT* PeContext);
STATUS DumpFileHeader(MY_IMAGE_FILE_HEADER* file_header);
STATUS DumpOptionalHeader(MY_IMAGE_OPTIONAL_HEADER64* optional_header);
STATUS DumpExportDirectory(PE_PARSED_EXPORT_DIRECTORY* parsed_export_directory);
STATUS DumpImportDescriptors(PE_PARSED_IMPORT_DESCRIPTOR* parsed_import_descriptors, uint32_t ImportDescsCount);
STATUS DumpSectionHeader(MY_IMAGE_SECTION_HEADER* sections_header, uint16_t NumberOfSections);

// Analysis Dumping
STATUS DumpEAT();

//--------------------------------Internal-Helpers--------------------------------------

// Ensure header does not exceed disk image boundaries
int IsValidRange(size_t DiskImageSize, uint32_t offset, uint32_t size);

// Resolve RVA to VA
// "inline" makes this function be a code text replacement instead of function call 
static inline uint8_t* RVA_TO_VA(uint8_t* base, uintptr_t rva) 
{
    return base + rva;
}

// Resolve Sections Offsets for Imports using an RVA
uint32_t RvaToOffset(uint32_t rva, MY_IMAGE_SECTION_HEADER* sections, uint16_t numSections);
