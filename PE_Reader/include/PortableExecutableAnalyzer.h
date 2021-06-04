#pragma once
#include "peanalyzer.h"
#include "constants.h"
#include "util.h"
#include "ImageHeaders.h"
#include <Zydis/Zydis.h>
#include <Windows.h>

class PortableExecutableAnalyzer
{
private:
	std::ifstream file_stream;
	std::vector<std::byte> buffer;
	std::byte dos_header[8];
	std::byte pe_signature[4];
	peanalyzer::IMAGE_FILE_HEADER file_header;
	peanalyzer::IMAGE_OPTIONAL_HEADER optional_header;
	std::vector<peanalyzer::SECTION_HEADER> section_headers;
	std::vector<peanalyzer::SECTION_DATA> section_data;
	std::vector<ZydisDecodedInstruction> instructions;
	std::string text_instructions;
	std::stringstream text_instruction_stream;
	std::size_t bytes_read;
	void SetImageFileHeaderFields(size_t offset);
	void SetOptionalHeaderFields(size_t offset);
	void SetSectionHeaders(size_t offset, uint32_t number_of_sections);
	void Disassemble(std::vector<std::byte>& buffer, uint64_t virtual_address, std::ostream& instruction_stream, std::vector<ZydisDecodedInstruction>& instruction_buffer);
	std::size_t AnalyzeFile();
	void MapFileToMemory();
	HANDLE file_handle;
	HANDLE file_mapping_handle;
	LPVOID mem_mapped_location;
	std::string file_path;
	template<typename T> void SetImportLookupTableData(uint64_t import_lookup_offset, uint64_t address, peanalyzer::IMPORT_INFO* import_info, peanalyzer::IMPORT_LOOKUP_TABLE& lookup_table);
	std::vector<peanalyzer::IMPORT_INFO> import_entries;
public:
	PortableExecutableAnalyzer(std::string& file_path);
	~PortableExecutableAnalyzer();
	peanalyzer::IMAGE_FILE_HEADER& GetFileHeader();
	const peanalyzer::IMAGE_FILE_HEADER& GetFileHeader() const;
	peanalyzer::IMAGE_OPTIONAL_HEADER& GetOptionalHeader();
	const peanalyzer::IMAGE_OPTIONAL_HEADER& GetOptionalHeader() const;
	std::vector<peanalyzer::SECTION_HEADER>& GetSectionHeaders();
	std::vector<peanalyzer::IMPORT_INFO>& GetImportInformation();
	std::string& GetTextSectionDisassembly();
	void WriteTextSectionDisassemblyToStream(std::ostream& out_stream);
	size_t GetBytesRead();
};