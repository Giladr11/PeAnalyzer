#include "../include/internals.h"


/*Per Import DLL*/
static STATUS DumpDllFunctions(char* dll_name, PE_PARSED_IMPORT_FUNCTION* parsed_import_functions, uint32_t functions_count)
{
        printf("\nDll Name: %s\n", dll_name);

        uint32_t count_check = 0;
        for (size_t i = 0; i < functions_count; i++)
        {
                printf("Function Name: %s, ", parsed_import_functions[i].FunctionName);
                printf("Ordinal: 0x%04X, ", parsed_import_functions[i].Ordinal);
                printf("IsOrdinal: 0x%02X, ", parsed_import_functions[i].IsOrdinal);
                printf("IAT Function Address: 0x%016llx\n", parsed_import_functions[i].IATAddress);
                
                count_check++;
        }
        
       return SUCCESS_STATUS;  
}


STATUS DumpImportDescriptors(PE_PARSED_IMPORT_DESCRIPTOR* parsed_import_descriptors, uint32_t ImportDescsCount)
{
        printf("\n========Import-Descriptors-Dumping=========");

        uint32_t count = 1;
        for (size_t i = 0; i < ImportDescsCount; i++)
        {
                printf("\nDll number: %d", count);
                if(DumpDllFunctions(parsed_import_descriptors[i].DllName, parsed_import_descriptors[i].Functions, parsed_import_descriptors[i].FunctionsCount) == ERROR_STATUS)
                {
                        return ERROR_STATUS;
                }
                count++;
        }

        return SUCCESS_STATUS;
}