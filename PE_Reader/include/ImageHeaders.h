#pragma once
#include "constants.h"
#include "peanalyzer.h"

namespace peanalyzer
{
	struct IMAGE_FILE_HEADER
	{
		constants::MachineType Machine = constants::MachineType::PE_IMAGE_FILE_MACHINE_AMD64;
		uint16_t NumberOfSections = 0;
		uint32_t TimeDateStamp = 0;
		uint32_t PointerToSymbolTable = 0;
		uint32_t NumberOfSymbols = 0;
		uint16_t SizeOfOptionalHeader = 0;
		uint16_t Characteristics = 0;
	};

	struct IMAGE_DATA_DIRECTORY
	{
		uint32_t VirtualAddress = 0;
		uint32_t Size = 0;
	};

	struct IMAGE_OPTIONAL_HEADER
	{
		peanalyzer::constants::PEBitness Magic = peanalyzer::constants::PEBitness::PE_IMAGE_NT_OPTIONAL_MAGIC_32;
		std::byte MajorLinkerVersion = std::byte{ 0x0 };
		std::byte MinorLinkerVersion = std::byte{ 0x0 };
		uint32_t SizeOfCode = 0;
		uint32_t SizeOfInitializedData = 0;
		uint32_t SizeOfUninitializedData = 0;
		uint32_t AddressOfEntryPoint = 0;
		uint32_t BaseOfCode = 0;
		uint32_t BaseOfData = 0;
		uint64_t ImageBase = 0;
		uint32_t SectionAlignment = 0;
		uint32_t FileAlignment = 0;
		uint16_t MajorOperatingSystemVersion = 0;
		uint16_t MinorOperatingSystemVersion = 0;
		uint16_t MajorImageVersion = 0;
		uint16_t MinorImageVersion = 0;
		uint16_t MajorSubsystemVersion = 0;
		uint16_t MinorSubsystemVersion = 0;
		uint32_t Win32VersionValue = 0;
		uint32_t SizeOfImage = 0;
		uint32_t SizeOfHeaders = 0;
		uint32_t CheckSum = 0;
		peanalyzer::constants::Subsystem Subsystem = peanalyzer::constants::Subsystem::PE_IMAGE_SUBSYSTEM_EFI_APPLICATION;
		uint16_t DllCharacteristics = 0;
		uint64_t SizeOfStackReserve = 0;
		uint64_t SizeOfStackCommit = 0;
		uint64_t SizeOfHeapReserve = 0;
		uint64_t SizeOfHeapCommit = 0;
		uint32_t LoaderFlags = 0;
		uint32_t NumberOfRvaAndSizes = 0;
		std::vector<IMAGE_DATA_DIRECTORY> DataDirectory;
	};

	struct SECTION_HEADER
	{
		std::string Name;
		uint32_t VirtualSize = 0;
		uint32_t VirtualAddress = 0;
		uint32_t SizeOfRawData = 0;
		uint32_t PointerToRawData = 0;
		uint32_t PointerToRelocations = 0;
		uint32_t PointerToLineNumbers = 0;
		uint32_t NumberOfRelocations = 0;
		uint32_t NumberOfLineNumbers = 0;
		uint32_t Characteristics = 0;
	};

	struct IMPORT_SECTION
	{
		uint32_t LookupTableRVA = 0;
		uint32_t Timestamp = 0;
		uint32_t ForwarderChain = 0;
		uint32_t NameRVA = 0;
		uint32_t AddressTableRVA = 0;
	};

	struct SECTION_DATA
	{
		std::string Name;
		std::vector<std::byte> Data;
	};

	struct IMPORT_DIRECTORY_TABLE
	{
		uint32_t ImportLookupTableRVA = 0;
		uint32_t Timestamp = 0;
		uint32_t ForwarderChain = 0;
		uint32_t NameRVA = 0;
		uint32_t ImportAddressTableRVA = 0;
	};

	struct RAW_IMPORT_LOOKUP_TABLE_64
	{
		uint64_t TableData;
	};

	struct RAW_IMPORT_LOOKUP_TABLE_32
	{
		uint32_t TableData;
	};

	struct IMPORT_LOOKUP_TABLE
	{
		bool ImportByOrdinal = false;
		uint16_t OrdinalNumber = 0;
		uint32_t HintNameTableRVA = 0;
	};

	struct IMPORT_INFO
	{
		IMPORT_DIRECTORY_TABLE TableEntry;
		std::string Name;
		std::vector<IMPORT_LOOKUP_TABLE> LookupTableEntries;
	};
}