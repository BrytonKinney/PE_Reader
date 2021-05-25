#include "PortableExecutableAnalyzer.h"

PortableExecutableAnalyzer::PortableExecutableAnalyzer(std::string& file_path)
{
	file_stream = std::ifstream(file_path, std::ios::binary | std::ios::ate);
	bytes_read = AnalyzeFile();
}

PortableExecutableAnalyzer::~PortableExecutableAnalyzer() {}

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
	return buffer.size();
}

void PortableExecutableAnalyzer::SetImageFileHeaderFields(size_t offset)
{
	using namespace peanalyzer::util;
	file_header.Machine = static_cast<peanalyzer::constants::MachineType>(from_bytes<unsigned short>(buffer.data() + offset));
	file_header.NumberOfSections = from_bytes<unsigned short>(buffer.data() + offset + 2);
	file_header.TimeDateStamp = from_bytes<unsigned int>(buffer.data() + offset + 4);
	file_header.PointerToSymbolTable = from_bytes<unsigned int>(buffer.data() + offset + 8);
	file_header.NumberOfSymbols = from_bytes<unsigned int>(buffer.data() + offset + 12);
	file_header.SizeOfOptionalHeader = from_bytes<unsigned short>(buffer.data() + offset + 16);
	file_header.Characteristics = from_bytes<unsigned short>(buffer.data() + offset + 18);
}

void PortableExecutableAnalyzer::SetOptionalHeaderFields(size_t offset)
{
	using namespace peanalyzer::util;
	optional_header.Magic = static_cast<peanalyzer::constants::PEBitness>(from_bytes<unsigned short>(buffer.data() + offset));
	optional_header.MajorLinkerVersion = buffer.at(offset + 2);
	optional_header.MinorLinkerVersion = buffer.at(offset + 3);
	optional_header.SizeOfCode = from_bytes<unsigned int>(buffer.data() + offset + 4);
	optional_header.SizeOfInitializedData = from_bytes<unsigned int>(buffer.data() + offset + 8);
	optional_header.SizeOfUninitializedData = from_bytes<unsigned int>(buffer.data() + offset + 12);
	optional_header.AddressOfEntryPoint = from_bytes<unsigned int>(buffer.data() + offset + 16);
	optional_header.BaseOfCode = from_bytes<unsigned int>(buffer.data() + offset + 20);
	if (optional_header.Magic == peanalyzer::constants::PEBitness::IMAGE_NT_OPTIONAL_MAGIC_32)
	{
		optional_header.BaseOfData = from_bytes<unsigned int>(buffer.data() + offset + 24);
		optional_header.ImageBase = from_bytes<unsigned int>(buffer.data() + offset + 28);
	}
	else
	{
		optional_header.ImageBase = from_bytes<unsigned long long>(buffer.data() + offset + 24);
	}
	optional_header.SectionAlignment = from_bytes<unsigned int>(buffer.data() + offset + 32);
	optional_header.FileAlignment = from_bytes<unsigned int>(buffer.data() + offset + 36);
	optional_header.MajorOperatingSystemVersion = from_bytes<unsigned short>(buffer.data() + offset + 40);
	optional_header.MinorOperatingSystemVersion = from_bytes<unsigned short>(buffer.data() + offset + 42);
	optional_header.MajorImageVersion = from_bytes<unsigned short>(buffer.data() + offset + 44);
	optional_header.MinorImageVersion = from_bytes<unsigned short>(buffer.data() + offset + 46);
	optional_header.MajorSubsystemVersion = from_bytes<unsigned short>(buffer.data() + offset + 48);
	optional_header.MinorSubsystemVersion = from_bytes<unsigned short>(buffer.data() + offset + 50);
	optional_header.Win32VersionValue = from_bytes<unsigned int>(buffer.data() + offset + 52);
	optional_header.SizeOfImage = from_bytes<unsigned int>(buffer.data() + offset + 56);
	optional_header.SizeOfHeaders = from_bytes<unsigned int>(buffer.data() + offset + 60);
	optional_header.CheckSum = from_bytes<unsigned int>(buffer.data() + offset + 64);
	optional_header.Subsystem = static_cast<peanalyzer::constants::Subsystem>(from_bytes<unsigned short>(buffer.data() + offset + 68));
	optional_header.DllCharacteristics = from_bytes<unsigned short>(buffer.data() + offset + 70);
	if (optional_header.Magic == peanalyzer::constants::PEBitness::IMAGE_NT_OPTIONAL_MAGIC_32)
	{
		optional_header.SizeOfStackReserve = from_bytes<unsigned int>(buffer.data() + offset + 72);
		optional_header.SizeOfStackCommit = from_bytes<unsigned int>(buffer.data() + offset + 76);
		optional_header.SizeOfHeapReserve = from_bytes<unsigned int>(buffer.data() + offset + 80);
		optional_header.SizeOfHeapReserve = from_bytes<unsigned int>(buffer.data() + offset + 84);
	}
	else
	{
		optional_header.SizeOfStackReserve = from_bytes<unsigned long long>(buffer.data() + offset + 72);
		optional_header.SizeOfStackCommit = from_bytes<unsigned long long>(buffer.data() + offset + 80);
		optional_header.SizeOfHeapReserve = from_bytes<unsigned long long>(buffer.data() + offset + 88);
		optional_header.SizeOfHeapReserve = from_bytes<unsigned long long>(buffer.data() + offset + 96);
		offset += 16;
	}
	optional_header.LoaderFlags = from_bytes<unsigned int>(buffer.data() + offset + 88);
	optional_header.NumberOfRvaAndSizes = from_bytes<unsigned int>(buffer.data() + offset + 92);
	offset += 96;
	if (optional_header.NumberOfRvaAndSizes > 0)
	{
		for (unsigned int i = 0; i < optional_header.NumberOfRvaAndSizes * 8; i += 8)
		{
			IMAGE_DATA_DIRECTORY instance;
			instance.VirtualAddress = from_bytes<unsigned int>(buffer.data() + offset + i);
			instance.Size = from_bytes<unsigned int>(buffer.data() + offset + i + 4);
			optional_header.DataDirectory.push_back(instance);
		}
	}
}

void PortableExecutableAnalyzer::SetSectionHeaders(size_t offset, unsigned int number_of_sections)
{
	using namespace peanalyzer::util;
	for (unsigned int sectionIndex = 0; sectionIndex < number_of_sections; sectionIndex++)
	{
		SECTION_HEADER section;
		section.Name = from_bytes(buffer, offset + (40 * sectionIndex), 8);
		section.Name.erase(std::find(section.Name.begin(), section.Name.end(), '\0'), section.Name.end());
		section.VirtualSize = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 8);
		section.VirtualAddress = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 12);
		section.SizeOfRawData = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 16);
		section.PointerToRawData = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 20);
		section.PointerToRelocations = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 24);
		section.PointerToLineNumbers = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 28);
		section.NumberOfRelocations = from_bytes<unsigned short>(buffer.data() + offset + (40 * sectionIndex) + 32);
		section.NumberOfLineNumbers = from_bytes<unsigned short>(buffer.data() + offset + (40 * sectionIndex) + 34);
		section.Characteristics = from_bytes<unsigned int>(buffer.data() + offset + (40 * sectionIndex) + 36);
		section_headers.push_back(section);
		SECTION_DATA local_section_data;
		local_section_data.Name = section.Name;
		for (std::size_t section_data_offset = section.PointerToRawData; section_data_offset < (section.PointerToRawData + section.SizeOfRawData); section_data_offset++)
		{
			local_section_data.Data.push_back(buffer.at(section_data_offset));
		}
		section_data.push_back(local_section_data);
		if (section.Name.compare(".text") == 0)
		{
			if (file_header.SizeOfOptionalHeader > 0)
			{
				Disassemble(local_section_data.Data, optional_header.ImageBase + section.VirtualAddress, text_instruction_stream);
			}
			else
			{
				Disassemble(local_section_data.Data, section.VirtualAddress, text_instruction_stream);
			}
			text_instructions = text_instruction_stream.str();
		}
	}
}

const IMAGE_FILE_HEADER& PortableExecutableAnalyzer::GetFileHeader() const
{
	return file_header;
}

IMAGE_FILE_HEADER& PortableExecutableAnalyzer::GetFileHeader()
{
	return file_header;
}

IMAGE_OPTIONAL_HEADER& PortableExecutableAnalyzer::GetOptionalHeader()
{
	return optional_header;
}

const IMAGE_OPTIONAL_HEADER& PortableExecutableAnalyzer::GetOptionalHeader() const
{
	return optional_header;
}

std::vector<SECTION_HEADER>& PortableExecutableAnalyzer::GetSectionHeaders()
{
	return section_headers;
}

void PortableExecutableAnalyzer::Disassemble(std::vector<std::byte>& buffer, unsigned long long virtual_address, std::ostream& instruction_stream)
{
	ZydisDecoder decoder;
	if (file_header.Machine == peanalyzer::constants::MachineType::IMAGE_FILE_MACHINE_AMD64)
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
		instructions.push_back(instruction);
	}
	arr -= arr_len;
	size_t num_instructions = instructions.size();
	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	int pos = 0;
	for (const ZydisDecodedInstruction& inst : instructions)
	{
		char buff[256];
		ZydisFormatterFormatInstruction(&formatter, &inst, buff, sizeof(buff), virtual_address);
		instruction_stream << "0x" << std::hex << virtual_address << " | ";
		for (int i = pos; i < pos + inst.length; i++) 
		{
			instruction_stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(buffer.at(i));
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