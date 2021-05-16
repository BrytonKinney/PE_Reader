#pragma once
#include "peanalyzer.h"
#include "constants.h"

struct IMAGE_FILE_HEADER
{
	peanalyzer::constants::MachineType Machine;
	unsigned short NumberOfSections;
	unsigned long TimeDateStamp;
	unsigned long PointerToSymbolTable;
	unsigned long NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
};

struct IMAGE_OPTIONAL_HEADER
{
	peanalyzer::constants::PEBitness Magic;
	std::byte MajorLinkerVersion;
	std::byte MinorLinkerVersion;
	unsigned long SizeOfCode;
	unsigned long SizeOfInitializedData;
	unsigned long SizeOfUninitializedData;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long BaseOfData;
	unsigned long long ImageBase;
	unsigned long SectionAlignment;
	unsigned long FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned long Win32VersionValue;
	unsigned long SizeOfImage;
	unsigned long SizeOfHeaders;
	unsigned long CheckSum;
	unsigned short Subsystem;
	unsigned short DllCharacteristics;
	unsigned long long SizeOfStackReserve;
	unsigned long long SizeOfStackCommit;
	unsigned long long SizeOfHeapReserve;
	unsigned long long SizeOfHeapCommit;
	unsigned long LoaderFlags;
	unsigned long NumberOfRvaAndSizes;
};

struct IMAGE_DATA_DIRECTORY 
{
	unsigned long VirtualAddress;
	unsigned long Size;
};