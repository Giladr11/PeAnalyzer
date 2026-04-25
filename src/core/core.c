#include "include/internals.h"


//============================================================Main-Handler============================================================

void* LoadPEDiskImage(char* PEpath, size_t* PE_size) 
{
    FILE* DiskPEImage = fopen(PEpath, "rb");

    if (!DiskPEImage)
    {
        fprintf(stderr, "[-] Failed to open file: %s\n", PEpath);
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

    if (PE_size)
        *PE_size = size;

    return buffer;
}

HANDLER* CreateHandler(void* PEbase, size_t PEsize) 
{
    HANDLER* handler = calloc(1, sizeof(HANDLER));
    if (!handler) 
    {
        return NULL;
    }

    handler->DiskPEImage = calloc(1, sizeof(PE_DISK_IMAGE));
    handler->PEContext = calloc(1, sizeof(PE_CONTEXT));

    handler->DiskPEImage->DiskImageBase = PEbase;
    handler->DiskPEImage->DiskImageSize = PEsize;
    
    return handler;
}
