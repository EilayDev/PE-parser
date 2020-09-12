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
	this->pDirectoryEntry_TLS = (PIMAGE_DATA_DIRECTORY)this->pDataDirectory + IMAGE_DIRECTORY_ENTRY_TLS;

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
int main(int argc, char* argv[]) {
	if (argc == 1) return 2;
	pe_parser parser(argv[1]);
	if (parser.isTLS_used()) {
		std::cout << "Is a gui!\n";
	}
	else {
		std::cout <<  "Is NOT gui!\n";
	}
	getchar();
	return 0;
}