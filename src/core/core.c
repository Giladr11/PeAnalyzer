#include "include/internals.h"


//=========================================================Main-Handler=========================================================

// Initialize handler object and read PE image from file
HANDLER* initPEAnalyzer(char* pe_path) 
{   
    fprintf(stdout, "==============================\n");
    fprintf(stdout, "[PHASE] Initiating PE Analyzer\n");
    fprintf(stdout, "==============================\n\n");
    
    size_t pe_size = 0;

    void* filebase = ReadPEDiskImage(pe_path, &pe_size);
    if (!filebase)
    {
        return NULL;
    }
    
    HANDLER* handler = InitializeHandler(filebase, pe_size);
    if (!handler)
    {
        return NULL;
    }

    return handler;
}


// Read PE from disk to RAM
void* ReadPEDiskImage(char* pe_path, size_t* pe_size) 
{
    FILE* DiskPEImage = fopen(pe_path, "rb");

    if (!DiskPEImage)
    {
        fprintf(stderr, "[-] Failed to open file: %s\n", pe_path);
        return NULL;
    }
    
    fseek(DiskPEImage, 0, SEEK_END);  // Set File offset to end to check size of file
    size_t size = ftell(DiskPEImage); // Check File Offset  
    rewind(DiskPEImage);              // Restore offset to start of file

    void* buffer = malloc(size);
    if (!buffer)
    {
        fclose(DiskPEImage);
        return NULL;
    }

    if (fread(buffer, 1, size, DiskPEImage) != size)
    {
        free(buffer);
        fclose(DiskPEImage);
        return NULL;
    }

    fclose(DiskPEImage);

    if (pe_size)
        *pe_size = size;

    return buffer;
}


// Initialize Handler Object
HANDLER* InitializeHandler(void* pe_base, size_t pe_size) 
{
    HANDLER* handler = calloc(1, sizeof(HANDLER));
    if (!handler) 
    {
        return NULL;
    }

    handler->DiskPEImage = calloc(1, sizeof(PE_DISK_IMAGE));
    handler->PEContext = calloc(1, sizeof(PE_CONTEXT));

    handler->DiskPEImage->DiskImageBase = pe_base;
    handler->DiskPEImage->DiskImageSize = pe_size;
    
    return handler;
}


void clean_heap(HANDLER* handler) 
{
    printf("\nCleaning Allocated heap memory...");
    FreeAnalysis(handler->PEContext->Analysis);
    FreeParsedExportDirectoryAnalysis(handler->PEContext->Analysis->ParsedExportDirectory);
    
    free(handler->PEContext->Headers->DosStub);
    free(handler->PEContext->Headers);
    
    free(handler->DiskPEImage);
    free(handler->PEContext);
    free(handler);
}
