#include "PortableExecutableAnalyzer.h"

PortableExecutableAnalyzer::PortableExecutableAnalyzer(std::string& file_path) 
{
	file_stream = std::ifstream(file_path, std::ios::binary | std::ios::ate);
}

PortableExecutableAnalyzer::~PortableExecutableAnalyzer()
{}

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
	// 0-64
	for (std::size_t dos_header_iterator = 0; dos_header_iterator < 8; dos_header_iterator++) 
	{
		dos_header[dos_header_iterator] = buffer.at(dos_header_iterator);
	}
	for (std::size_t pe_signature_iterator = pe_signature_offset; pe_signature_iterator < pe_signature_offset + 4; pe_signature_iterator++)
	{
		pe_signature[pe_signature_iterator - pe_signature_offset] = buffer.at(pe_signature_iterator);
	}
	for (std::size_t iter = image_file_header_offset; iter < image_file_header_offset + 20; iter++) 
	{
		image_file_header[iter - image_file_header_offset] = buffer.at(iter);
	}
	machine_type = static_cast<constants::MachineType>(util::short_from_bytes(image_file_header, 0));
	SetImageFileHeaderFields();
	SetOptionalHeaderFields(optional_header_offset);
	return buffer.size();
}

peanalyzer::constants::MachineType& PortableExecutableAnalyzer::GetMachineType()
{
	return machine_type;
}

unsigned short PortableExecutableAnalyzer::GetNumberOfSections()
{
	return peanalyzer::util::short_from_bytes(image_file_header + 2);
}

unsigned long PortableExecutableAnalyzer::GetTimestamp()
{
	return peanalyzer::util::long_from_bytes(image_file_header + 4);
}

unsigned long PortableExecutableAnalyzer::GetPointerToSymbolTable()
{
	return peanalyzer::util::long_from_bytes(image_file_header + 8);
}

unsigned long PortableExecutableAnalyzer::GetNumberOfSymbols()
{
	return peanalyzer::util::long_from_bytes(image_file_header + 12);
}

unsigned short PortableExecutableAnalyzer::GetSizeOfOptionalHeader()
{
	return peanalyzer::util::short_from_bytes(image_file_header + 16);
}

unsigned short PortableExecutableAnalyzer::GetCharacteristics()
{
	return peanalyzer::util::short_from_bytes(image_file_header + 18);
}

void PortableExecutableAnalyzer::SetImageFileHeaderFields()
{
	file_header.Machine = machine_type;
	file_header.NumberOfSections = GetNumberOfSections();
	file_header.TimeDateStamp = GetTimestamp();
	file_header.PointerToSymbolTable = GetPointerToSymbolTable();
	file_header.NumberOfSymbols = GetNumberOfSymbols();
	file_header.SizeOfOptionalHeader = GetSizeOfOptionalHeader();
	file_header.Characteristics = GetCharacteristics();
}

void PortableExecutableAnalyzer::SetOptionalHeaderFields(size_t offset)
{
	using namespace peanalyzer::util;
	optional_header.Magic = static_cast<peanalyzer::constants::PEBitness>(short_from_bytes(buffer.data() + offset));
	optional_header.MajorLinkerVersion = buffer.at(offset + 2);
	optional_header.MinorLinkerVersion = buffer.at(offset + 3);
	optional_header.SizeOfCode = long_from_bytes(buffer.data() + offset + 4);
	optional_header.SizeOfInitializedData = long_from_bytes(buffer.data() + offset + 8);
	optional_header.SizeOfUninitializedData = long_from_bytes(buffer.data() + offset + 12);
	optional_header.AddressOfEntryPoint = long_from_bytes(buffer.data() + offset + 16);
	optional_header.BaseOfCode = long_from_bytes(buffer.data() + offset + 20);
	optional_header.ImageBase = u64_from_bytes(buffer.data() + offset + 24);
	optional_header.SectionAlignment = long_from_bytes(buffer.data() + offset + 32);
	optional_header.FileAlignment = long_from_bytes(buffer.data() + offset + 36);
	optional_header.MajorOperatingSystemVersion = short_from_bytes(buffer.data() + offset + 40);
	optional_header.MinorOperatingSystemVersion = short_from_bytes(buffer.data() + offset + 42);
	optional_header.MinorOperatingSystemVersion = short_from_bytes(buffer.data() + offset + 44);
	optional_header.MajorImageVersion = short_from_bytes(buffer.data() + offset + 46);
	optional_header.MinorImageVersion = short_from_bytes(buffer.data() + offset + 48);
	optional_header.MajorSubsystemVersion = short_from_bytes(buffer.data() + offset + 50);
	optional_header.MinorOperatingSystemVersion = short_from_bytes(buffer.data() + offset + 52);
	optional_header.Win32VersionValue = long_from_bytes(buffer.data() + offset + 54);
	optional_header.SizeOfImage = long_from_bytes(buffer.data() + offset + 58);
	optional_header.SizeOfHeaders = long_from_bytes(buffer.data() + offset + 62);
	optional_header.CheckSum = long_from_bytes(buffer.data() + offset + 66);
	optional_header.Subsystem = short_from_bytes(buffer.data() + offset + 70);
	optional_header.DllCharacteristics = short_from_bytes(buffer.data() + offset + 72);
	if (optional_header.Magic == peanalyzer::constants::PEBitness::IMAGE_NT_OPTIONAL_MAGIC_32)
	{
		optional_header.SizeOfStackReserve = long_from_bytes(buffer.data() + offset + 74);
		optional_header.SizeOfStackCommit = long_from_bytes(buffer.data() + offset + 78);
		optional_header.SizeOfHeapReserve = long_from_bytes(buffer.data() + offset + 82);
		optional_header.SizeOfHeapReserve = long_from_bytes(buffer.data() + offset + 86);
		optional_header.LoaderFlags = long_from_bytes(buffer.data() + offset + 90);
		optional_header.NumberOfRvaAndSizes = long_from_bytes(buffer.data() + offset + 94);
	}
	else
	{
		optional_header.SizeOfStackReserve = u64_from_bytes(buffer.data() + offset + 74);
		optional_header.SizeOfStackCommit = u64_from_bytes(buffer.data() + offset + 82);
		optional_header.SizeOfHeapReserve = u64_from_bytes(buffer.data() + offset + 90);
		optional_header.SizeOfHeapReserve = u64_from_bytes(buffer.data() + offset + 98);
		optional_header.LoaderFlags = long_from_bytes(buffer.data() + offset + 106);
		optional_header.NumberOfRvaAndSizes = long_from_bytes(buffer.data() + offset + 114);
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