#include "parser.h"

pe_parser::pe_parser(LPCSTR filePath) {
	std::ifstream file(filePath, std::ios::in | std::ios::binary | std::ios::ate);
	size_t size = file.tellg();
	this->szFile = size;
	file.seekg(0, std::ios::beg);

	char* buffer = new char[size];
	file.read(buffer, size);
	file.close();
	this->pDOS_Header = (IMAGE_DOS_HEADER*)buffer;
	this->pNT_Header = (IMAGE_NT_HEADERS*)(this->pDOS_Header->e_lfanew + buffer);
	if (pNT_Header->Signature != NT_SIGNATURE) {
		throw "Not an executable!";
	}

	// Parsing Headers
	this->pFileHeader = (IMAGE_FILE_HEADER*)&this->pNT_Header->FileHeader;
	this->pOptional_Header = (IMAGE_OPTIONAL_HEADER*)&pNT_Header->OptionalHeader;
	
	// Parsing DataDirectory
	this->pDataDirectory[0] = (IMAGE_DATA_DIRECTORY*)&this->pOptional_Header->DataDirectory;
	for (int i = 1; i < 16; i++) {
		this->pDataDirectory[i] = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory[i-1] + 1;
	}

	// Parsing Sections
	this->numberOfSections = (int)this->pFileHeader->NumberOfSections;
	this->sectionHeaders[this->numberOfSections];
	this->sectionHeaders[0] = (IMAGE_SECTION_HEADER*)((LPVOID)(this->pNT_Header + 1));
	for (int i = 1; i < this->numberOfSections; i++) {
		this->sectionHeaders[i] = (IMAGE_SECTION_HEADER*)(this->sectionHeaders[i-1] + 1);
	}
	
	this->dataDirectories.pExport_Directory = (PIMAGE_EXPORT_DIRECTORY)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]->VirtualAddress);;
	this->dataDirectories.pImport_Descriptor = (PIMAGE_IMPORT_DESCRIPTOR)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]->VirtualAddress);;
	this->dataDirectories.pResource_Directory = (PIMAGE_RESOURCE_DIRECTORY)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]->VirtualAddress);;
	this->dataDirectories.pRelocation_Directory = (PIMAGE_BASE_RELOCATION)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]->VirtualAddress);;
	this->dataDirectories.pDebug_Directory = (PIMAGE_DEBUG_DIRECTORY)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]->VirtualAddress);;
	this->dataDirectories.pTLS_Directory = (PIMAGE_TLS_DIRECTORY)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]->VirtualAddress);;
	this->dataDirectories.pBoundImport_Descriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]->VirtualAddress);;
	this->dataDirectories.pDelayLoad_Descriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)this->correctAddress(this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]->VirtualAddress);;
	// TODO FIX: YOU ASSUMED ALL FUNCTIONS ARE NAMED FUNCTIONS!!!~~!!~!~!~!
	// Getting Export Information
	if (isExporting()) {
		this->numberOfExportedFunctions = dataDirectories.pExport_Directory->NumberOfFunctions;
		for (int i = 0; i < this->numberOfExportedFunctions; i++) {
			this->ExportedFunctions[i].functionRVA = *(DWORD*)(LPVOID)(this->correctAddress(this->dataDirectories.pExport_Directory->AddressOfFunctions + i*4));
			this->ExportedFunctions[i].NameOrdinal = *(DWORD*)this->correctAddress(this->dataDirectories.pExport_Directory->AddressOfNameOrdinals + i * 4);
			this->ExportedFunctions[i].Name = *(DWORD*)this->correctAddress(this->dataDirectories.pExport_Directory->AddressOfNames + i * 4);
			// dereference
			this->ExportedFunctions[i].de_functionRVA = (LPVOID)this->correctAddress(this->ExportedFunctions[i].functionRVA);
			this->ExportedFunctions[i].de_Name = (LPCSTR)correctAddress(this->ExportedFunctions[i].Name);
		}
		std::cout << this->ExportedFunctions[10].de_Name << "\n";
	}
}
LPVOID pe_parser::correctAddress(DWORD VirtualAddress) {
	for (int i = 0; i < this->numberOfSections; i++) {
		DWORD sVA = this->sectionHeaders[i]->VirtualAddress;
		DWORD vSz = this->sectionHeaders[i]->Misc.VirtualSize;
		DWORD pRD = this->sectionHeaders[i]->PointerToRawData;
		DWORD dVA = VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { return (LPVOID)(dVA - sVA + pRD + (DWORDLONG)this->pDOS_Header); }
	}
}

int main(int argc, char* argv[]) {
	if (argc == 1) { return 1; }
	pe_parser parser(argv[1]);
	
	getchar();
	return 0;
}



/*
	// Parsing dataDirectories enteries
	for (int i = 0; i < this->numberOfSections; i++) {
		// Formula: DataDirectory[x].VirtualAddress >= Sections[i].VirtualAddress && [x].VirtualAddress <= Sections[i].VirtualAddr + sections[i].Misc.VirtualSize
		DWORD sVA = this->sectionHeaders[i]->VirtualAddress;
		DWORD vSz = this->sectionHeaders[i]->Misc.VirtualSize;
		DWORD pRD = this->sectionHeaders[i]->PointerToRawData;
		DWORD dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]->VirtualAddress;
		// pExport_Directory
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pExport_Directory = (PIMAGE_EXPORT_DIRECTORY)(LPVOID)(dVA - sVA + pRD + buffer); }
		// pImport
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pImport_Descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(LPVOID)(dVA - sVA + pRD + buffer); }
		// pResource
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pResource_Directory = (PIMAGE_RESOURCE_DIRECTORY)(LPVOID)(dVA - sVA + pRD + buffer); }
		// Relocation
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pRelocation_Directory = (PIMAGE_BASE_RELOCATION)(LPVOID)(dVA - sVA + pRD + buffer); }
		// Debug
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pDebug_Directory = (PIMAGE_DEBUG_DIRECTORY)(LPVOID)(dVA - sVA + pRD + buffer); }
		// TLS
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pTLS_Directory = (PIMAGE_TLS_DIRECTORY)(LPVOID)(dVA - sVA + pRD + buffer); }
		// Bound Import
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pBoundImport_Descriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(LPVOID)(dVA - sVA + pRD + buffer); }
		// DelayLOAD
		dVA = this->pDataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]->VirtualAddress;
		if (dVA >= sVA && dVA <= sVA + vSz) { this->dataDirectories.pDelayLoad_Descriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)(LPVOID)(dVA - sVA + pRD + buffer); }
	}
	*/