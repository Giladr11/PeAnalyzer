#include "../include/internals.h"


/*Only for DLL files*/
STATUS DumpExportDirectory(PE_PARSED_EXPORT_DIRECTORY* parsed_export_directory) {
        for (size_t i = 0; i < parsed_export_directory->EATCount; i++) 
        {
            printf("Exported function: %s", (char*)(parsed_export_directory->EAT + i));     
        }

       return SUCCESS_STATUS;  
}