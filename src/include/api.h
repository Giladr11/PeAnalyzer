// Public Structs & API

#pragma once

#include <stdint.h>
#include "pe_headers.h"
 

//-----------------------------------Public-Structs-----------------------------------

typedef struct {
    uint8_t* DiskImageBase;
    size_t DiskImageSize;
} PE_DISK_IMAGE;

typedef struct {
    // DOS
    MY_IMAGE_DOS_HEADER* DosHeader;

    // NT
    MY_IMAGE_NT_HEADERS64* NtHeaders;
    MY_IMAGE_FILE_HEADER* FileHeader;
    MY_IMAGE_OPTIONAL_HEADER64* OptionalHeader;

    // DataDirectory Indexes
    MY_IMAGE_EXPORT_DIRECTORY* ExportDirectory;
    MY_IMAGE_IMPORT_DESCRIPTOR* ImportDescriptors;

    // Sections
    MY_IMAGE_SECTION_HEADER* SectionHeaders;
} PE_HEADERS_CONTEXT;

//----------------Export&Import-Structs----------------

// EAT
typedef struct {
    uint32_t* EAT;                                             // Export Address Table (Array of RVAs to exported functions in (.edata/.rdara))
    uint32_t EATCount;                                         // Number of exported functions in EAT
        
    uint32_t* AddressOfNames;                                  // Names Array of all Exported Functions 
    uint32_t NumberOfNames;                                    // Size of AddressOfNames Array = Size of AddressOfNameOrdinals Array 
        
    uint32_t OrdinalsBase;                                     // First export ordinal value (used as offset for EAT indexing) (ordinal - OrdinalBase)
    uint32_t* AddressOfNameOrdinals;                           // Stores Ordinals which after conversation are then used as EAT[ordinal] to access the Exported Functions
} PE_PARSED_EXPORT_DIRECTORY;                      
        
// (INT/IAT) Per Imported DLL
// Per DLL Function
typedef struct {
    char* FunctionName;                                        // resolved name (if any)
    uint16_t Ordinal;                                          // if ordinal import
    uint8_t IsOrdinal;                                         // flag
    uint64_t IATAddress;                                       // resolved runtime address slot
} PE_PARSED_IMPORT_FUNCTION;

// Per DLL
typedef struct {                           
    char* DllName;                                             // Imported module name (DLL)
        
    MY_IMAGE_THUNK_DATA64* INT;                                // Import Name Table (OriginalFirstThunk) – requested imports (names/ordinals) in (.idata)
    MY_IMAGE_THUNK_DATA64* IAT;                                // Import Address Table (FirstThunk) – resolved function addresses at runtime in (.idata)   
    
    PE_PARSED_IMPORT_FUNCTION* Functions;                      // Parsed Functions in a Single DLL
    uint32_t FunctionsCount;                                   // Functions Count in a Single DLL
} PE_PARSED_IMPORT_DESCRIPTOR;             

// Parsed PE (Import/Export) Analysis Results 
typedef struct {                
    PE_PARSED_EXPORT_DIRECTORY* ParsedExportDirectory;         // Export Address Table (EAT) analysis results
    PE_PARSED_IMPORT_DESCRIPTOR* ParsedImportDescriptors;      // Per-DLL import entries (INT/IAT grouped per module) analysis results

    uint32_t ImportDescsCount;                                 // Number of Import Descriptors
} ANALYSIS_CONTEXT;             

//-----------------------------------------------------

typedef enum {
    STATUS_SUCCESS  = 0,
    STATUS_ERROR    = -1
} STATUS;

// Parser Object
typedef struct {                
    PE_HEADERS_CONTEXT* Headers;                               // Raw PE structures (headers, sections, directories as parsed from the binary)    
    ANALYSIS_CONTEXT* Analysis;                                // Parsed analysis results (INT/IAT/EAT and resolved import/export information)
} PE_CONTEXT;                          
     
typedef struct {                           
    PE_DISK_IMAGE* DiskPEImage;                                     // Raw PE File
    PE_CONTEXT* PEContext;                                     // Parsed PE File
} HANDLER;


//------------------------------------Public-APIs-------------------------------------
// Core
void* LoadPEDiskImage(char* PEpath, size_t* outSizes);
HANDLER* CreateHandler(void* base, size_t size);

// Main Parser
int MainPEHeadersParser(HANDLER* handler);                     // Headers Parsing *(Executing the Parsers)*

// Main Dumper
int MainPEContextDumper(PE_CONTEXT* PEContext);                // PE Dumping *(Printing the PE_CONTEXT that was established)*

// Ownership Models
void FreeAnalysis(ANALYSIS_CONTEXT* a);
void FreeParsedExportDirectoryAnalysis(PE_PARSED_EXPORT_DIRECTORY* a);
