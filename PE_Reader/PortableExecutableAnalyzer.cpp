#include "PortableExecutableAnalyzer.h"
PortableExecutableAnalyzer::PortableExecutableAnalyzer(std::string& file_path)
{
	file_stream = std::ifstream(file_path, std::ios::binary | std::ios::ate);
	this->file_path = file_path;
	bytes_read = AnalyzeFile();
}

PortableExecutableAnalyzer::~PortableExecutableAnalyzer() 
{
	if (CloseHandle(this->file_handle) == 0)
		std::cout << "Failed to close file handle: " << GetLastError();
	if (CloseHandle(this->file_mapping_handle) == 0)
		std::cout << "Failed to close file mapping handle: " << GetLastError();
}

std::size_t PortableExecutableAnalyzer::AnalyzeFile()
{
	using namespace peanalyzer;
	if (!file_stream)
		return 0;
	std::streampos file_end = file_stream.tellg();
	file_stream.seekg(0, std::ios::beg);
	std::size_t size = std::size_t(file_end - file_stream.tellg());
	if (size == 0)
		return 0;
	buffer = std::vector<std::byte>(size);
	if (!file_stream.read((char*)buffer.data(), buffer.size()))
		return 0;
	std::size_t pe_signature_offset = static_cast<std::size_t>(buffer.at(0x3C));
	std::size_t image_file_header_offset = pe_signature_offset + 4;
	std::size_t optional_header_offset = image_file_header_offset + 20;
	for (std::size_t dos_header_iterator = 0; dos_header_iterator < 8; dos_header_iterator++)
	{
		dos_header[dos_header_iterator] = buffer.at(dos_header_iterator);
	}
	for (std::size_t pe_signature_iterator = pe_signature_offset; pe_signature_iterator < pe_signature_offset + 4; pe_signature_iterator++)
	{
		pe_signature[pe_signature_iterator - pe_signature_offset] = buffer.at(pe_signature_iterator);
	}
	SetImageFileHeaderFields(image_file_header_offset);
	std::size_t section_header_offset = optional_header_offset;
	if (file_header.SizeOfOptionalHeader > 0)
	{
		SetOptionalHeaderFields(optional_header_offset);
		optional_header_offset += file_header.SizeOfOptionalHeader;
	}
	SetSectionHeaders(optional_header_offset, file_header.NumberOfSections);
	MapFileToMemory();
	return buffer.size();
}

void PortableExecutableAnalyzer::SetImageFileHeaderFields(size_t offset)
{
	using namespace peanalyzer::util;
	file_header.Machine = static_cast<peanalyzer::constants::MachineType>(from_bytes<uint16_t>(buffer.data() + offset));
	file_header.NumberOfSections = from_bytes<uint16_t>(buffer.data() + offset + 2);
	file_header.TimeDateStamp = from_bytes<uint32_t>(buffer.data() + offset + 4);
	file_header.PointerToSymbolTable = from_bytes<uint32_t>(buffer.data() + offset + 8);
	file_header.NumberOfSymbols = from_bytes<uint32_t>(buffer.data() + offset + 12);
	file_header.SizeOfOptionalHeader = from_bytes<uint16_t>(buffer.data() + offset + 16);
	file_header.Characteristics = from_bytes<uint16_t>(buffer.data() + offset + 18);
}

void PortableExecutableAnalyzer::SetOptionalHeaderFields(size_t offset)
{
	using namespace peanalyzer::util;
	optional_header.Magic = static_cast<peanalyzer::constants::PEBitness>(from_bytes<uint16_t>(buffer.data() + offset));
	optional_header.MajorLinkerVersion = buffer.at(offset + 2);
	optional_header.MinorLinkerVersion = buffer.at(offset + 3);
	optional_header.SizeOfCode = from_bytes<uint32_t>(buffer.data() + offset + 4);
	optional_header.SizeOfInitializedData = from_bytes<uint32_t>(buffer.data() + offset + 8);
	optional_header.SizeOfUninitializedData = from_bytes<uint32_t>(buffer.data() + offset + 12);
	optional_header.AddressOfEntryPoint = from_bytes<uint32_t>(buffer.data() + offset + 16);
	optional_header.BaseOfCode = from_bytes<uint32_t>(buffer.data() + offset + 20);
	if (optional_header.Magic == peanalyzer::constants::PEBitness::PE_IMAGE_NT_OPTIONAL_MAGIC_32)
	{
		optional_header.BaseOfData = from_bytes<uint32_t>(buffer.data() + offset + 24);
		optional_header.ImageBase = from_bytes<uint32_t>(buffer.data() + offset + 28);
	}
	else
	{
		optional_header.ImageBase = from_bytes<uint64_t>(buffer.data() + offset + 24);
	}
	optional_header.SectionAlignment = from_bytes<uint32_t>(buffer.data() + offset + 32);
	optional_header.FileAlignment = from_bytes<uint32_t>(buffer.data() + offset + 36);
	optional_header.MajorOperatingSystemVersion = from_bytes<uint16_t>(buffer.data() + offset + 40);
	optional_header.MinorOperatingSystemVersion = from_bytes<uint16_t>(buffer.data() + offset + 42);
	optional_header.MajorImageVersion = from_bytes<uint16_t>(buffer.data() + offset + 44);
	optional_header.MinorImageVersion = from_bytes<uint16_t>(buffer.data() + offset + 46);
	optional_header.MajorSubsystemVersion = from_bytes<uint16_t>(buffer.data() + offset + 48);
	optional_header.MinorSubsystemVersion = from_bytes<uint16_t>(buffer.data() + offset + 50);
	optional_header.Win32VersionValue = from_bytes<uint32_t>(buffer.data() + offset + 52);
	optional_header.SizeOfImage = from_bytes<uint32_t>(buffer.data() + offset + 56);
	optional_header.SizeOfHeaders = from_bytes<uint32_t>(buffer.data() + offset + 60);
	optional_header.CheckSum = from_bytes<uint32_t>(buffer.data() + offset + 64);
	optional_header.Subsystem = static_cast<peanalyzer::constants::Subsystem>(from_bytes<uint16_t>(buffer.data() + offset + 68));
	optional_header.DllCharacteristics = from_bytes<uint16_t>(buffer.data() + offset + 70);
	if (optional_header.Magic == peanalyzer::constants::PEBitness::PE_IMAGE_NT_OPTIONAL_MAGIC_32)
	{
		optional_header.SizeOfStackReserve = from_bytes<uint32_t>(buffer.data() + offset + 72);
		optional_header.SizeOfStackCommit = from_bytes<uint32_t>(buffer.data() + offset + 76);
		optional_header.SizeOfHeapReserve = from_bytes<uint32_t>(buffer.data() + offset + 80);
		optional_header.SizeOfHeapReserve = from_bytes<uint32_t>(buffer.data() + offset + 84);
	}
	else
	{
		optional_header.SizeOfStackReserve = from_bytes<uint64_t>(buffer.data() + offset + 72);
		optional_header.SizeOfStackCommit = from_bytes<uint64_t>(buffer.data() + offset + 80);
		optional_header.SizeOfHeapReserve = from_bytes<uint64_t>(buffer.data() + offset + 88);
		optional_header.SizeOfHeapReserve = from_bytes<uint64_t>(buffer.data() + offset + 96);
		offset += 16;
	}
	optional_header.LoaderFlags = from_bytes<uint32_t>(buffer.data() + offset + 88);
	optional_header.NumberOfRvaAndSizes = from_bytes<uint32_t>(buffer.data() + offset + 92);
	offset += 96;
	if (optional_header.NumberOfRvaAndSizes > 0)
	{
		for (uint32_t i = 0; i < optional_header.NumberOfRvaAndSizes * 8; i += 8)
		{
			peanalyzer::IMAGE_DATA_DIRECTORY instance;
			instance.VirtualAddress = from_bytes<uint32_t>(buffer.data() + offset + i);
			instance.Size = from_bytes<uint32_t>(buffer.data() + offset + i + 4);
			optional_header.DataDirectory.push_back(instance);
		}
	}
}

void PortableExecutableAnalyzer::SetSectionHeaders(size_t offset, uint32_t number_of_sections)
{
	using namespace peanalyzer::util;
	for (uint32_t sectionIndex = 0; sectionIndex < number_of_sections; sectionIndex++)
	{
		peanalyzer::SECTION_HEADER section;
		section.Name = from_bytes(buffer, offset + (40 * sectionIndex), 8);
		section.Name.erase(std::find(section.Name.begin(), section.Name.end(), '\0'), section.Name.end());
		section.VirtualSize = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 8);
		section.VirtualAddress = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 12);
		section.SizeOfRawData = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 16);
		section.PointerToRawData = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 20);
		section.PointerToRelocations = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 24);
		section.PointerToLineNumbers = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 28);
		section.NumberOfRelocations = from_bytes<uint16_t>(buffer.data() + offset + (40 * sectionIndex) + 32);
		section.NumberOfLineNumbers = from_bytes<uint16_t>(buffer.data() + offset + (40 * sectionIndex) + 34);
		section.Characteristics = from_bytes<uint32_t>(buffer.data() + offset + (40 * sectionIndex) + 36);
		section_headers.push_back(section);
		peanalyzer::SECTION_DATA local_section_data;
		local_section_data.Name = section.Name;
		// offset = pointer to data in file, while offset - (data offset + size), increment offset
		for (std::size_t section_data_offset = section.PointerToRawData; section_data_offset < (section.PointerToRawData + section.SizeOfRawData); section_data_offset++)
		{
			local_section_data.Data.push_back(buffer.at(section_data_offset));
		}
		section_data.push_back(local_section_data);
		if (section.Name.compare(".text") == 0)
		{
			if (file_header.SizeOfOptionalHeader > 0)
			{
				Disassemble(local_section_data.Data, optional_header.ImageBase + section.VirtualAddress, text_instruction_stream, instructions);
			}
			else
			{
				Disassemble(local_section_data.Data, section.VirtualAddress, text_instruction_stream, instructions);
			}
			text_instructions = text_instruction_stream.str();
		}
		else if (section.Name.compare(".rdata") == 0)
		{
			std::vector<uint8_t> widths;
			std::byte last_byte{ 0 };
			for (size_t rdata_iter = 0; rdata_iter < (size_t)section.SizeOfRawData; rdata_iter++)
			{
				std::byte current_byte = local_section_data.Data.at(rdata_iter);
				if (static_cast<char>(current_byte) != '\0' && static_cast<char>(last_byte) == '\0')
				{
					widths.push_back(rdata_iter);
				}
				last_byte = current_byte;
			}
		}
	}
}

const peanalyzer::IMAGE_FILE_HEADER& PortableExecutableAnalyzer::GetFileHeader() const
{
	return file_header;
}

peanalyzer::IMAGE_FILE_HEADER& PortableExecutableAnalyzer::GetFileHeader()
{
	return file_header;
}

peanalyzer::IMAGE_OPTIONAL_HEADER& PortableExecutableAnalyzer::GetOptionalHeader()
{
	return optional_header;
}

const peanalyzer::IMAGE_OPTIONAL_HEADER& PortableExecutableAnalyzer::GetOptionalHeader() const
{
	return optional_header;
}

std::vector<peanalyzer::SECTION_HEADER>& PortableExecutableAnalyzer::GetSectionHeaders()
{
	return section_headers;
}

void PortableExecutableAnalyzer::Disassemble(std::vector<std::byte>& buffer, uint64_t virtual_address, std::ostream& instruction_stream, std::vector<ZydisDecodedInstruction>& instruction_buffer)
{
	ZydisDecoder decoder;
	if (file_header.Machine == peanalyzer::constants::MachineType::PE_IMAGE_FILE_MACHINE_AMD64)
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
	else
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
	ZyanUSize offset = 0;
	ZyanUSize length = buffer.size();
	ZyanUSize arr_len = buffer.size();
	ZydisDecodedInstruction instruction;
	ZyanU8* arr = new ZyanU8[arr_len];
	for (int i = 0; i < arr_len; i++)
	{
		arr[i] = static_cast<ZyanU8>(buffer.at(i));
	}
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, arr, length, &instruction)))
	{
		arr += instruction.length;
		length -= instruction.length;
		instruction_buffer.push_back(instruction);
	}
	arr -= (arr_len - length);
	size_t num_instructions = instruction_buffer.size();
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	int pos = 0;
	for (const ZydisDecodedInstruction& inst : instruction_buffer)
	{
		char buff[256];
		ZydisFormatterFormatInstruction(&formatter, &inst, buff, sizeof(buff), virtual_address);
		instruction_stream << "0x" << std::hex << virtual_address << " | ";
		for (int i = pos; i < pos + inst.length; i++) 
		{
			instruction_stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<uint32_t>(buffer.at(i));
			if (i < pos + inst.length - 1)
				instruction_stream << " ";
		}
		for (int j = 25; j > inst.length * 3 + 1; j--)
		{
			instruction_stream << " ";
		}
		pos += inst.length;
		instruction_stream << " | " << std::dec << buff;
		if (pos % 50 == 0)
			instruction_stream << std::endl;
		else
			instruction_stream << "\n";
		virtual_address += inst.length;
	}
	delete[] arr;
}

std::string& PortableExecutableAnalyzer::GetTextSectionDisassembly()
{
	return text_instructions;
}

void PortableExecutableAnalyzer::WriteTextSectionDisassemblyToStream(std::ostream& out_stream)
{
	out_stream << text_instructions;
}

size_t PortableExecutableAnalyzer::GetBytesRead()
{
	return bytes_read;
}

void PortableExecutableAnalyzer::MapFileToMemory()
{
	// all of this is so unsafe, yet I lack the knowledge and desire to rework it
	std::wstring file_path_w = std::wstring(file_path.begin(), file_path.end());
	this->file_handle = CreateFile(file_path_w.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (file_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Invalid file handle. " << GetLastError() << std::endl;
		return;
	}
	this->file_mapping_handle = CreateFileMapping(file_handle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, L"PE_View");
	if (file_mapping_handle == NULL)
	{
		std::cout << "Unable to map file to memory. " << GetLastError() << std::endl;
		return;
	}
	else
	{
		mem_mapped_location = MapViewOfFile(file_mapping_handle, FILE_MAP_READ, 0, 0, 0);
		if (mem_mapped_location == nullptr)
			return;
		DWORD dwLength = *((LPDWORD)mem_mapped_location);
		char* char_mapped_loc = static_cast<char*>(mem_mapped_location);
		uint64_t idata_location = reinterpret_cast<uint64_t>(char_mapped_loc) + optional_header.DataDirectory[1].VirtualAddress;
		// 5 fields * 4 byte width = 20
		for (uint64_t offset_iterator = idata_location; offset_iterator < optional_header.DataDirectory[1].Size + idata_location; offset_iterator += 20)
		{
			peanalyzer::IMPORT_DIRECTORY_TABLE idt;
			idt.ImportLookupTableRVA = *reinterpret_cast<uint32_t*>(offset_iterator);
			idt.Timestamp = *reinterpret_cast<uint32_t*>(offset_iterator + 4);
			idt.ForwarderChain = *reinterpret_cast<uint32_t*>(offset_iterator + 8);
			idt.NameRVA = *reinterpret_cast<uint32_t*>(offset_iterator + 12);
			idt.ImportAddressTableRVA = *reinterpret_cast<uint32_t*>(offset_iterator + 16);
			import_directory_table.push_back(idt);
		}
	}
}

std::vector<peanalyzer::IMPORT_DIRECTORY_TABLE>& PortableExecutableAnalyzer::GetImportDirectoryTable()
{
	return import_directory_table;
}