#pragma once
#include <stdexcept>
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <string>

#define MZ_MAGIC				0x5A4D
#define NT_SIGNATURE			0x4550
#define MACHINE_x64				0x8664
#define MACHINE_x86				0x014c
#define OPTIONAL_HDRS_MAGIC_64	IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define OPTIONAL_HDRS_MAGIC_32	IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGEBASE_DLL			0x10000000
#define IMAGEBASE_EXE			0x00400000
#define NUMBER_OF_DATA_DIRECTORIES 15
	
extern struct pe_parser {
	pe_parser(LPCSTR filePath);

	bool isDll() {
		return((this->pFileHeader->Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) ? true : false;
	}
	bool is_x64() {
		return (this->pFileHeader->Machine == MACHINE_x64) ? true : false;
	}
	bool isGUI() { // Does the program have a GUI?
		return (!pe_parser::isDll() && this->pOptional_Header->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) ? (true) : (false);
	}
	bool isCUI() { // Does the program run under a commandline?
		return (!pe_parser::isDll() && this->pOptional_Header->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) ? (true) : (false);

	}
	bool isTLS_used() { // is the TLS being used
			return (this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]->VirtualAddress == NULL) ? false : true;
	}
	

	int numberOfSections;
	size_t szFile;
	LPVOID baseAddress = pDOS_Header;

	// Main Headers
	IMAGE_DOS_HEADER* pDOS_Header;
	IMAGE_NT_HEADERS* pNT_Header;
	
	// Parent-> pNT_Header
	IMAGE_FILE_HEADER* pFileHeader;
	IMAGE_OPTIONAL_HEADER* pOptional_Header;

	// Parent -> optional header
	IMAGE_DATA_DIRECTORY* pDataDirectory[16];
	
	struct dataDirectory {
		PIMAGE_EXPORT_DIRECTORY		pExport_Directory;			// Parent -> EXPORT
		PIMAGE_IMPORT_DESCRIPTOR	pImport_Descriptor;
		PIMAGE_RESOURCE_DIRECTORY	pResource_Directory;
		PIMAGE_BASE_RELOCATION		pRelocation_Directory;		// Parent -> BaseReloc
		PIMAGE_DEBUG_DIRECTORY		pDebug_Directory;			// Parent -> Debug
		PIMAGE_TLS_DIRECTORY		pTLS_Directory;				// Parent -> TLS
		PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImport_Descriptor;
		PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoad_Descriptor;		// Parent -> DelayImport
	}; dataDirectory dataDirectories;

	IMAGE_SECTION_HEADER* sectionHeaders[];
private:
	//void locateData(int sectionNumber, DWORD dataVirtualAddress);
};
