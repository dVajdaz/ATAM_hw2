#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

Elf64_Shdr getSectionHeader(Elf64_Ehdr ELF_header, FILE* file, char* sectionName){
    Elf64_Shdr currentSection, stringTableHeader;
    char currentName[8];

    fseek(file, ELF_header.e_shoff, SEEK_SET);                                          //file indicator pointing to section header table
    fseek(file,  ELF_header.e_shstrndx * ELF_header.e_shentsize,  SEEK_CUR);            //file indicator pointing to entry for the section name string table
    fread(&stringTableHeader, sizeof(stringTableHeader), 1, file);
    //fseek(file, ELF_header.e_shoff, SEEK_SET);                                        //file indicator pointing to section header

    for(int i = 0; i<=ELF_header.e_shnum - 1; i++){
        fseek(file,  ELF_header.e_shoff  +  i * ELF_header.e_shentsize,  SEEK_SET);     //iterating through section header table
        fread(&currentSection, sizeof(currentSection), 1, file);

        fseek(file,  stringTableHeader.sh_offset + currentSection.sh_name,  SEEK_SET);  //file indicator pointing to the name of the current section
        fread(&currentName, sizeof(char), 8, file);

        if(strcmp(currentName, sectionName) == 0){
            //fseek(file,  ELF_header.e_shoff  +  i * ELF_header.e_shentsize,  SEEK_SET);
            break;
        }
    }

    fseek(file,  0,  SEEK_SET);
    return currentSection;
    /*
    if(strcmp(currentName, sectionName) == 0){
        fseek(file,  0,  SEEK_SET);
        return currentSection;
    } else {}
    */
}

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    //------------------FILE PARSING------------------
    //printf("\nSEARCHING FOR %s", symbol_name);
    FILE* file;
    file = fopen(exe_file_name , "r");

    Elf64_Ehdr E_header;
    fread(&E_header, sizeof(E_header), 1, file);

    //check if the file is an executable
    if(E_header.e_type != 2){
        *error_val = -3;
        return 0;
    }

    //------------------SYMBOL SEARCHING------------------
    Elf64_Shdr symtabHeader = getSectionHeader(E_header, file, ".symtab");
    Elf64_Shdr strtabHeader = getSectionHeader(E_header, file, ".strtab");

    Elf64_Sym currentSymbol, globalSymbolFound;
    char currentSymbolName[strlen(symbol_name) + 1];
    bool found, localExists, globalExists;

    for(int i = 0; i<symtabHeader.sh_size / symtabHeader.sh_entsize; i++){
        fseek(file,  symtabHeader.sh_offset + symtabHeader.sh_entsize*i,  SEEK_SET);    //file indicator pointing to the entry of the current symbol in symtable
        fread(&currentSymbol, sizeof(currentSymbol), 1, file);

        fseek(file,  strtabHeader.sh_offset + currentSymbol.st_name,  SEEK_SET);        //file indicator pointing to the entry of the current symbol in strtable
        fread(&currentSymbolName, sizeof(char), strlen(symbol_name) + 1, file);

        //printf("\nCURRENT SYMBOL NAME: %s", currentSymbolName);

        if(strcmp(currentSymbolName, symbol_name) == 0){
            found = true;

            if(currentSymbol.st_shndx == SHN_UNDEF) {
                *error_val = -4;
                return 0;
            }

            if(ELF64_ST_BIND(currentSymbol.st_info) == 1){
                globalSymbolFound = currentSymbol;
                globalExists = true;
                break;
            }else{
                localExists = true;
            }
        }
    }

    if(!found){
        *error_val = -1;
    }else if(localExists && !globalExists){
        *error_val = -2;
    }else{
        *error_val = 1;
    }

    //------------------VIRTUAL ADDRESS RETRIEVAL------------------
    Elf64_Addr virtualAddress = globalSymbolFound.st_value;

    fclose(file);
	return virtualAddress;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}