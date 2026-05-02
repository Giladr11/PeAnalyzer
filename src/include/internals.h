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
int DosHeaderParser(HANDLER* handler);

// Extract DOS Stub Header ("This program cannot be run in DOS mode.")
int DosStubParser(HANDLER* handler);

int NTHeadersParser(HANDLER* handler);
int FileHeaderParser(MY_IMAGE_FILE_HEADER* pFileHeader);
int OptionalHeaderInitializer(HANDLER* handler);
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


int SectionHeadersParser(HANDLER* handler);


//----------------------------Internal-Context-Dumping----------------------------------

// Context Dumping
int DumpDosHeader(PE_CONTEXT* PEContext);
int DumpDosStub(PE_CONTEXT* PEContext);
int DumpNTHeaders(PE_CONTEXT* PEContext);
int DumpFileHeader(PE_CONTEXT* PEContext);
int DumpOptionalHeader(PE_CONTEXT* PEContext);

// Analysis Dumping
int DumpEAT();
int DumpINT();
int DumpIAT();


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
