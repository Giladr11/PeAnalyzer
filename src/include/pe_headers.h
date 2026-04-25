#pragma once

#include <stdint.h>

#pragma pack(push, 1)                                  // PE Format is byte-accurate on disk, so compiler padding must be disabled to match the binary layout exactly.

/////////////////////////////////////////////////////////////////////PE-Headers/////////////////////////////////////////////////////////////////////
// 'Optional Header' Magic
#define MY_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x10B
#define PAGE_SIZE_X64 0x1000                           // Page size in RAM is a box of exactly 4096 bytes

// The Max Length of 'section' Name in PE in bytes
#define IMAGE_SIZEOF_SHORT_NAME 8 

// Signatures *(Magic Numbers)*
#define MY_IMAGE_DOS_SIGNATURE  0x5A4D                 // DOS Signature
#define MY_IMAGE_NT_SIGNATURE   0x00004550             // PE Signature

// The Size of DataDirectory at the end of Optional Headers
#define MY_IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16           

// Data Directory Indexes
#define MY_IMAGE_DIRECTORY_ENTRY_EXPORT          0     // Points to IMAGE_EXPORT_DIRECTORY (export metadata of DLL)
#define MY_IMAGE_DIRECTORY_ENTRY_IMPORT          1     // Points to IMAGE_IMPORT_DESCRIPTOR array (import metadata of EXE/DLL)
#define MY_IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define MY_IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define MY_IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define MY_IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define MY_IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define MY_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define MY_IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define MY_IMAGE_DIRECTORY_ENTRY_TLS             9
#define MY_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG     10
#define MY_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT    11
#define MY_IMAGE_DIRECTORY_ENTRY_IAT             12    // Index of IAT Table inside .idata section ('import data' section) 
#define MY_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT    13
#define MY_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR  14 


// MS-DOS Header          
typedef struct {          
    uint16_t e_magic;                                  // Magic number: 0x5A4D or MZ *(in little endians)*
    uint16_t e_cblp;                                   // Bytes on last page of file
    uint16_t e_cp;                                     // Pages in file
    uint16_t e_crlc;                                   // Relocations
    uint16_t e_cparhdr;                                // Size of header, in paragraphs
    uint16_t e_minalloc;                               // Min - extra paragraphs needed
    uint16_t e_maxalloc;                               // Max - extra paragraphs needed
    uint16_t e_ss;                                     // Initial (relative) SS value
    uint16_t e_sp;                                     // Initial SP value
    uint16_t e_csum;                                   // Checksum
    uint16_t e_ip;                                     // Initial IP value
    uint16_t e_cs;                                     // Initial (relative) CS value
    uint16_t e_lfarlc;                                 // File address of relocation table
    uint16_t e_ovno;                                   // Overlay number
    uint16_t e_res[4];                                 // Reserved words
    uint16_t e_oemid;                                  // OEM identifier
    uint16_t e_oeminfo;                                // OEM information
    uint16_t e_res2[10];                               // Reserved words
    int32_t e_lfanew;                                  // NT Header Offset, used for [(Image_base_Address AKA "MS-DOS offset") + e_lfanew]
} MY_IMAGE_DOS_HEADER;            


// File Header *(Part of NT Headers)*           
typedef struct {              
    uint16_t Machine;                                  // Machine Architecture type ("IMAGE_FILE_MACHINE_I386" -> x86)
    uint16_t NumberOfSections;                         // Sections table Size (.text .data, .bss .idata .edata .rdata)
    uint32_t TimeDateStamp;                            // PE Creation Timestamp Recorded by the Linker "ld" (invoked by the GCC driver) 
    uint32_t PointerToSymbolTable;                     // The Offset of the Symbol table in bytes
    uint32_t NumberOfSymbols;                          // The Number of Symbols in the Symbol Table
    uint16_t SizeOfOptionalHeader;                     // Size of the Optional Headers (Third element of the NT-HEADER)
    uint16_t Characteristics;                          // Defines the type/s of the IMAGE (exe, dll, sys etc...) -> ("IMAGE_FILE_DLL" -> This PE is a DLL File)
} MY_IMAGE_FILE_HEADER;           


// Data Directory's Entry Header *(Part of Optional Header -> Inside NT Headers)*
typedef struct {
    uint32_t VirtualAddress;                           // RVA that points to the start of the DataDircetory Entry (e.g. IMAGE_DIRECTORY_ENTRY_IAT -> index 12 of DataDirectory)
    uint32_t Size;                                     // The Size of the Data Directory in Bytes
} MY_IMAGE_DATA_DIRECTORY;


// Optional Header *(Part of NT Headers)*           
typedef struct {          
    uint16_t Magic;                                    // Determines if the PE is 32bits, 64bits or ROM Image
    uint8_t MajorLinkerVersion;                        // The Major release version number (e.g. 14 in 14.2 version) of the Linker used to create this PE
    uint8_t MinorLinkerVersion;                        // The Minor release version number (e.g. 2 in 14.2 version) of the Linker used to create this PE
    uint32_t SizeOfCode;                               // The Size of the code section (.text)
    uint32_t SizeOfInitializedData;                    // The Size of the initialized data section (.data)
    uint32_t SizeOfUninitializedData;                  // The Size of the uninitialized data section (.bss) 
    uint32_t AddressOfEntryPoint;                      // The RVA (Relative Virtual Address) of the EXE entry point inside .text (e.g. _start or mainCRTStartup) -> [(Image_base_Address AKA "MS-DOS offset") + AddressOfEntryPoint]
    uint32_t BaseOfCode;                               // RVA to the start of the code section (.text) after Loader loads PE to RAM. **("AddressOfEntryPoint" points to somewhere inside .text)**
    uint64_t ImageBase;                                // The preferred Address for MS-DOS Header Offset. Rarely used due to Loader's ASLR Protections
    uint32_t SectionAlignment;                         // The alignment (in bytes) of sections when loaded into RAM (e.g., 0x1000 or 4KB)
    uint32_t FileAlignment;                            // The alignment (in bytes) of sections in the file on disk (e.g., 0x200 or 512 bytes)
    uint16_t MajorOperatingSystemVersion;              // The major version number of the required OS (e.g., 6 for Windows Vista/7/10)
    uint16_t MinorOperatingSystemVersion;              // The minor version number of the required OS
    uint16_t MajorImageVersion;                        // User-definable major version number of the executable
    uint16_t MinorImageVersion;                        // User-definable minor version number of the executable
    uint16_t MajorSubsystemVersion;                    // The major version of the subsystem (e.g., 6 for modern Windows GUI/Console)
    uint16_t MinorSubsystemVersion;                    // The minor version of the subsystem
    uint32_t Win32VersionValue;                        // Reserved field, must be set to 0
    uint32_t SizeOfImage;                              // The total size (in bytes) of the PE image in memory, including all headers and padded sections
    uint32_t SizeOfHeaders;                            // The combined size of the MS-DOS Header, PE Header, and Section Headers, rounded up to FileAlignment
    uint32_t CheckSum;                                 // The image file checksum (used for drivers and critical system DLLs)
    uint16_t Subsystem;                                // The subsystem required to run the image (e.g., 2 for GUI, 3 for Console)
    uint16_t DllCharacteristics;                       // Flags for security and behavior (e.g., ASLR, NX/DEP, and Control Flow Guard)
    uint64_t SizeOfStackReserve;                       // The total amount of virtual memory to reserve for the initial thread's stack
    uint64_t SizeOfStackCommit;                        // The amount of physical memory initially allocated (committed) for the stack
    uint64_t SizeOfHeapReserve;                        // The total amount of virtual memory to reserve for the process heap
    uint64_t SizeOfHeapCommit;                         // The amount of physical memory initially allocated (committed) for the heap
    uint32_t LoaderFlags;                              // Obsolete field, typically set to 0
    uint32_t NumberOfRvaAndSizes;                      // The Number of entries in the DataDirectory array (16)
    MY_IMAGE_DATA_DIRECTORY DataDirectory[MY_IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // Array of RVA/Size pairs for major tables (Imports, Exports, IAT, etc..)
} MY_IMAGE_OPTIONAL_HEADER64; 


// NT Headers
typedef struct {
    uint32_t Signature;                                // 4 Bytes PE Signature (0x50450000 -> 'PE00') in little endian
    MY_IMAGE_FILE_HEADER FileHeader;                   // Contains Critical information About the PE File 
    MY_IMAGE_OPTIONAL_HEADER64 OptionalHeader;         // Specifices the Optional Header
} MY_IMAGE_NT_HEADERS64;


//-------------------------------------------------Import/Export Tables & IAT/INT------------------------------------------------


// Import Descriptor *(DataDirectory[1])* -> Represents a Single DLL Imported to the EXE
typedef struct {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;                   // RVA To A Specific DLL INT(Import Name Table) Entry *(Uses MY_IMAGE_THUNK_DATA64)*
    } ;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                                     // RVA to ASCII string containing the DLL name (e.g. "kernel32.dll")
    uint32_t FirstThunk;                               // RVA To A Specific DLL IAT(Import Address Table) Entry *(Uses MY_IMAGE_THUNK_DATA64)* (Before Loading the IAT value could be the same as INT and After loading it changes to address according to EAT)
} MY_IMAGE_IMPORT_DESCRIPTOR;


// A single thunk entry used in both INT and IAT (per imported DLL function)
// Referenced by 'OriginalFirstThunk' (INT) and 'FirstThunk' (IAT) FROM THE 'MY_IMAGE_IMPORT_DESCRIPTOR'
typedef struct {
    union {
        uint64_t ForwarderString;                      // RVA to a string used if the function is forwarded to another DLL
	    uint64_t Function;                             // IATThunks: Filled by the Windows loader with the resolved function address; on disk it is usually a copy of INT (RVA/thunk data), not a real address 
	    uint64_t Ordinal;                              // Function ordinal (number) used when importing by number instead of name; Used to import by ordinal; resolved as (Ordinal - Base) to index into the Export Address Table.
	    uint64_t AddressOfData;                        // INTThunks: RVA to an IMAGE_IMPORT_BY_NAME structure (used when importing by name) : Inside INT 
      } u1;
} MY_IMAGE_THUNK_DATA64;


// Each Entry in INT Points to this Header *(also used in IAT before Loading)*
typedef struct {
    uint16_t hint;                                     // Hint to speed up lookup; suggests a starting index in the export name table, but the loader may ignore it and fall back to name matching
    char Name[1];                                      // The Dll's Function Name used by the Loader to Retrieve the function address in the dll EAT to put in the IAT (INT → Name → Export Name Table in the dll → Ordinal → EAT → Function Address) *(Shown like this in memory: [hint][C][r][e][a][t][e][F][i][l][e][A][\0])*
} MY_IMAGE_IMPORT_BY_NAME;


// Export Directory (DataDirectory[0]) -> Describes all exported functions of a single PE (EAT, Name Table, Ordinals)
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t   MajorVersion;
    uint16_t   MinorVersion;

    uint32_t Name;                                     // DLL name (e.g. "kernel32.dll")
    uint32_t Base;                                     // First export ordinal value (used as offset for EAT indexing)
    uint32_t NumberOfFunctions;                        // Size of EAT
    uint32_t NumberOfNames;                            // Size of 'Export Name Table'
    uint32_t AddressOfFunctions;                       // EAT (Export Address Table) (like IAT for Export)
    uint32_t AddressOfNames;                           // 'Export Name Table' (like INT for Export)
    uint32_t AddressOfNameOrdinals;                    // Name → Ordinal mapping (The Actual Index of the function inside EAT)
} MY_IMAGE_EXPORT_DIRECTORY;

// EAT Flow: 
// Find function name: AddressOfNames[i]
// Use the same 'i' index to get the ordinal: AddressOfNameOrdinals[i]
// Convert Ordinal -> EAT index: ordinal - Base (Base is )
// Use the ordinal to access that function in EAT: AddressOfFunctions[AddressOfNameOrdinals[i]]


//-------------------------------------------------------------------------------------------------------------------------------


// Section Header
typedef struct {
  uint8_t  Name[IMAGE_SIZEOF_SHORT_NAME];              // Name of the section (e.g. .text)
  union {
    uint32_t PhysicalAddress;                               
    uint32_t VirtualSize;
  } Misc;                                              // The size of the section when its in memory
  uint32_t VirtualAddress;                             // The RVA where this section Starts in memory 
  uint32_t SizeOfRawData;                              // The size of the section on disk
  uint32_t PointerToRawData;                           // File pointer to the first page of the section
  uint32_t PointerToRelocations;                       // File pointer to the beginning of the relocation entries for the section
  uint32_t PointerToLinenumbers;                       // File pointer to the beginning of the line-number entries for the section
  uint16_t  NumberOfRelocations;                       // The number of relocation entries. For executables, this is set to zero (0)
  uint16_t  NumberOfLinenumbers;                       // Number of line-number entries for the section. This is no longer used and is set to zero (0)
  uint32_t Characteristics;                            // A Duint16_t(uint32_t) that uses flags to signal various characteristics of the PE
} MY_IMAGE_SECTION_HEADER;


#pragma pack(pop)                                      // Restore old padding Settings
