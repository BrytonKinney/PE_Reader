#pragma once
#include "constants.h"
#include "peanalyzer.h"

struct IMAGE_FILE_HEADER
{
	peanalyzer::constants::MachineType Machine;
	unsigned short NumberOfSections;
	unsigned int TimeDateStamp;
	unsigned int PointerToSymbolTable;
	unsigned int NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
};

struct IMAGE_DATA_DIRECTORY
{
	unsigned int VirtualAddress = 0;
	unsigned int Size = 0;
};

struct IMAGE_OPTIONAL_HEADER
{
	peanalyzer::constants::PEBitness Magic;
	std::byte MajorLinkerVersion = std::byte{ 0x0 };
	std::byte MinorLinkerVersion = std::byte{ 0x0 };
	unsigned int SizeOfCode = 0;
	unsigned int SizeOfInitializedData = 0;
	unsigned int SizeOfUninitializedData = 0;
	unsigned int AddressOfEntryPoint = 0;
	unsigned int BaseOfCode = 0;
	unsigned int BaseOfData = 0;
	unsigned long long ImageBase = 0;
	unsigned int SectionAlignment = 0;
	unsigned int FileAlignment = 0;
	unsigned short MajorOperatingSystemVersion = 0;
	unsigned short MinorOperatingSystemVersion = 0;
	unsigned short MajorImageVersion = 0;
	unsigned short MinorImageVersion = 0;
	unsigned short MajorSubsystemVersion = 0;
	unsigned short MinorSubsystemVersion = 0;
	unsigned int Win32VersionValue = 0;
	unsigned int SizeOfImage = 0;
	unsigned int SizeOfHeaders = 0;
	unsigned int CheckSum = 0;
	peanalyzer::constants::Subsystem Subsystem;
	unsigned short DllCharacteristics = 0;
	unsigned long long SizeOfStackReserve = 0;
	unsigned long long SizeOfStackCommit = 0;
	unsigned long long SizeOfHeapReserve = 0;
	unsigned long long SizeOfHeapCommit = 0;
	unsigned int LoaderFlags = 0;
	unsigned int NumberOfRvaAndSizes = 0;
	std::vector<IMAGE_DATA_DIRECTORY> DataDirectory;
};

struct SECTION_HEADER
{
	std::string Name;
	unsigned int VirtualSize;
	unsigned int VirtualAddress;
	unsigned int SizeOfRawData;
	unsigned int PointerToRawData;
	unsigned int PointerToRelocations;
	unsigned int PointerToLineNumbers;
	unsigned int NumberOfRelocations;
	unsigned int NumberOfLineNumbers;
	unsigned int Characteristics;
};

struct IMPORT_SECTION
{
	unsigned int LookupTableRVA;
	unsigned int Timestamp;
	unsigned int ForwarderChain;
	unsigned int NameRVA;
	unsigned int AddressTableRVA;
};

struct SECTION_DATA
{
	std::string Name;
	std::vector<std::byte> Data;
};