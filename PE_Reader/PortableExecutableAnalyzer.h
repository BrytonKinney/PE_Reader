#pragma once
#include "peanalyzer.h"
#include "constants.h"
#include "util.h"
#include "ImageHeaders.h"
#include <Zydis/Zydis.h>

class PortableExecutableAnalyzer 
{
private:
	std::ifstream file_stream;
	std::vector<std::byte> buffer;
	std::byte dos_header[8];
	std::byte pe_signature[4];
	IMAGE_FILE_HEADER file_header;
	IMAGE_OPTIONAL_HEADER optional_header;
	std::vector<SECTION_HEADER> section_headers;
	std::vector<SECTION_DATA> section_data;
	std::vector<ZydisDecodedInstruction> instructions;
	std::string text_instructions;
	std::stringstream text_instruction_stream;
	std::size_t bytes_read;
	void SetImageFileHeaderFields(size_t offset);
	void SetOptionalHeaderFields(size_t offset);
	void SetSectionHeaders(size_t offset, unsigned int number_of_sections);
	void Disassemble(std::vector<std::byte>& buffer, unsigned long long virtual_address, std::ostream& instruction_stream);
	std::size_t AnalyzeFile();
public:
	PortableExecutableAnalyzer(std::string& file_path);
	~PortableExecutableAnalyzer();
	IMAGE_FILE_HEADER& GetFileHeader();
	const IMAGE_FILE_HEADER& GetFileHeader() const;
	IMAGE_OPTIONAL_HEADER& GetOptionalHeader();
	const IMAGE_OPTIONAL_HEADER& GetOptionalHeader() const;
	std::vector<SECTION_HEADER>& GetSectionHeaders();
	std::string& GetTextSectionDisassembly();
	void WriteTextSectionDisassemblyToStream(std::ostream& out_stream);
	size_t GetBytesRead();
};