// Internal Structs & API

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "pe_headers.h"


//--------------------------------Internal-Structs--------------------------------------

typedef enum {
    STATUS_SUCCESS  = 0,
    STATUS_ERROR    = -1
} STATUS;

typedef struct {
    MY_IMAGE_EXPORT_DIRECTORY* ExportDirectory;        // Pointer to raw Export Directory (DataDirectory[0])
    MY_IMAGE_IMPORT_DESCRIPTOR* ImportDescriptors;     // Pointer to raw Import Descriptors array (DataDirectory[1])

    ANALYSIS_CONTEXT* Analysis;                        // Parsed (Import/Export) Analysis results (EAT & (INT/IAT per-DLL))

    STATUS status;                                     // Parsing/validation status for export/import processing
} TABLES_ANALYSIS_RESULTS;


//----------------------------Internal-Parsing-Routines---------------------------------

// Parse Functions *(Validate & Map (PE headers & RVAs) from 'RawImage' into a 'PEObj')*
int DosHeaderParser(HANDLER* handler);

int NTHeadersParser(HANDLER* handler);
int FileHeaderParser(MY_IMAGE_FILE_HEADER* pFileHeader);
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
int DumpDosHeader(MY_IMAGE_DOS_HEADER* dosHeader);
int DumpNTHeaders(MY_IMAGE_NT_HEADERS64* ntHeaders);
int DumpFileHeader(MY_IMAGE_FILE_HEADER* fileHeader);
int DumpOptionalHeader(MY_IMAGE_OPTIONAL_HEADER64* optionalHeader);

// Analysis Dumping
int DumpEAT();
int DumpINT();
int DumpIAT();


//--------------------------------Internal-Helpers--------------------------------------

// Extract DOS Stub Header ("This program cannot be run in DOS mode.")
int ExtractDosStub(HANDLER* handler);

// Ensures header does not exceed disk image boundaries
int IsValidRange(size_t DiskImageSize, uint32_t offset, uint32_t size);

// "inline" makes this function be a code text replacement instead of function call 
static inline uint8_t* RVA_TO_VA(uint8_t* base, uintptr_t rva) 
{
    return base + rva;
}
