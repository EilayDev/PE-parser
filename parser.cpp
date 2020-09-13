#include "parser.h"

pe_parser::pe_parser(LPCSTR filePath) {
	std::ifstream file(filePath, std::ios::in | std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	char* buffer = new char[READ_BYTES];
	file.read(buffer, READ_BYTES);
	file.close();
	this->pDOS_Header = (IMAGE_DOS_HEADER*)buffer;
	this->pNT_Header = (IMAGE_NT_HEADERS*)(this->pDOS_Header->e_lfanew + buffer);
	if (pNT_Header->Signature != NT_SIGNATURE) {
		throw "Not an executable!";
	}
	this->pFileHeader = (IMAGE_FILE_HEADER*)&this->pNT_Header->FileHeader;
	this->pOptional_Header = (IMAGE_OPTIONAL_HEADER*)&pNT_Header->OptionalHeader;
	this->pDataDirectory = (IMAGE_DATA_DIRECTORY*)&this->pOptional_Header->DataDirectory;
	this->pDirectoryEntry_EXPORT =		(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_EXPORT;
	this->pDirectoryEntry_IMPORT =		(PIMAGE_DATA_DIRECTORY)&this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_IMPORT;
	this->pDirectoryEntry_Resource =	(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_RESOURCE;
	this->pDirectoryEntry_Exception =	(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	this->pDirectoryEntry_Security =	(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_SECURITY;
	this->pDirectoryEntry_BaseReloc =	(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_BASERELOC;
	this->pDirectoryEntry_Debug =		(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_DEBUG;
	this->pDirectoryEntry_Architecture = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_ARCHITECTURE;
	this->pDirectoryEntry_GlobalPtr =	(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_GLOBALPTR;
	this->pDirectoryEntry_TLS =			(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_TLS;
	this->pDirectoryEntry_Config =		(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
	this->pDirectoryEntry_BoundImport = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT;
	this->pDirectoryEntry_IAT =			(PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_IAT;
	this->pDirectoryEntry_DelayImport = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory +			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;
	this->pDirectoryEntry_COM_Descriptor = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory +		IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
	
	int numberOfSections(getNumberOfSections());
	this->sectionHeaders[numberOfSections];
	this->sectionHeaders[0] = (IMAGE_SECTION_HEADER*)((LPVOID)(this->pNT_Header + 1));
	for (int i = 1; i < numberOfSections; i++) {
		this->sectionHeaders[i] = (IMAGE_SECTION_HEADER*)(this->sectionHeaders[i-1] + 1);
	}
}
bool pe_parser::isDll() {
	return((this->pFileHeader->Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) ? true : false;
}
bool pe_parser::is_x64() {
	return (this->pFileHeader->Machine == MACHINE_x64) ? true : false;
}
bool pe_parser::isCUI() {
	return (!pe_parser::isDll() && this->pOptional_Header->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) ? (true) : (false);
}
bool pe_parser::isGUI() {
	return (!pe_parser::isDll() && this->pOptional_Header->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) ? (true) : (false);
}
bool pe_parser::isTLS_used() {
	return (this->pDirectoryEntry_TLS->VirtualAddress == NULL) ? false : true;
}
int pe_parser::getNumberOfSections() {
	return (int)this->pFileHeader->NumberOfSections;
}

int main(int argc, char* argv[]) {
	if (argc == 1) return 2;
	pe_parser parser(argv[1]);
	// Testing here

	getchar();
	return 0;
}