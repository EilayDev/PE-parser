#pragma once
#include <stdexcept>
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <string>

#define READ_BYTES 4096
#define MZ_MAGIC 0x5A4D
#define NT_SIGNATURE 0x4550
#define MACHINE_x64 0x8664
#define MACHINE_x86 0x014c
#define OPTIONAL_HDRS_MAGIC_64 IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define OPTIONAL_HDRS_MAGIC_32 IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGEBASE_DLL 0x10000000
#define IMAGEBASE_EXE 0x00400000

int initiate();


	
class pe_parser {
public:
	pe_parser(LPCSTR filePath);
	// IS THE FILE A DLL?
	bool isDll();
	bool is_x64();
	// Does the program have a GUI?
	bool isGUI();
	// Does the program run under a commandline?
	bool isCUI();
	// is the TLS being used
	bool isTLS_used();

	// Main Headers
	IMAGE_DOS_HEADER* pDOS_Header;
	IMAGE_NT_HEADERS* pNT_Header;
	IMAGE_SECTION_HEADER* pSections; // Should be an array

	// Parent-> pNT_Header
	IMAGE_FILE_HEADER* pFileHeader;
	IMAGE_OPTIONAL_HEADER* pOptional_Header;

	// Parent -> optional header
	IMAGE_DATA_DIRECTORY* pDataDirectory; // Should be array

	// Parent -> DataDirectory
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_EXPORT;			// 0
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_IMPORT;			// 1
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Resource;			// 2
		// Parent -> Resource Directory
		IMAGE_RESOURCE_DIRECTORY* pResource_Directory;
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Exception;		// 3
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Security;			// 4
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_BaseReloc;		// 5
		// Parent -> BaseReloc
		IMAGE_BASE_RELOCATION* pRelocation_Directory;
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Debug;			// 6
		// Parent -> Debug
		IMAGE_DEBUG_DIRECTORY* pDebug_Directory;
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Copyright;		// 7
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_GlobalPtr;		// 8
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_TLS;				// 9
		// Parent -> TLS
		IMAGE_TLS_DIRECTORY* pTLS_Directory;
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_Config;			// 10
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_BoundImport;		// 11
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_IAT;				// 12
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_DelayImport;		// 13
		// Parent -> DelayImport
		IMAGE_DELAYLOAD_DESCRIPTOR* pDelayLoad_Descriptor;
	PIMAGE_DATA_DIRECTORY pDirectoryEntry_COM_Descriptor;	// 14



private:

	struct peHandle {
		std::ifstream file;
	};

};
