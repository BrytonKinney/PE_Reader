#pragma once
#include "peanalyzer.h"
#include "constants.h"
#include "util.h"
#include "ImageHeaders.h"

class PortableExecutableAnalyzer 
{
private:
	std::ifstream file_stream;
	std::vector<std::byte> buffer;
	std::byte dos_header[8];
	std::byte pe_signature[4];
	std::byte image_file_header[20];
	peanalyzer::constants::MachineType machine_type;
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER optional_header;
	void SetImageFileHeaderFields();
	void SetOptionalHeaderFields(size_t offset);
public:
	PortableExecutableAnalyzer(std::string& file_path);
	~PortableExecutableAnalyzer();
	std::size_t AnalyzeFile();
	peanalyzer::constants::MachineType& GetMachineType();
	unsigned short GetNumberOfSections();
	unsigned long GetTimestamp();
	unsigned long GetPointerToSymbolTable();
	unsigned long GetNumberOfSymbols();
	unsigned short GetSizeOfOptionalHeader();
	unsigned short GetCharacteristics();
	IMAGE_FILE_HEADER& GetFileHeader();
	const IMAGE_FILE_HEADER& GetFileHeader() const;
	IMAGE_OPTIONAL_HEADER& GetOptionalHeader();
	const IMAGE_OPTIONAL_HEADER& GetOptionalHeader() const;
};