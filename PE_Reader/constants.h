#pragma once
namespace peanalyzer
{
	namespace constants 
	{
		enum class MachineType : unsigned short
		{
			IMAGE_FILE_MACHINE_I386 = 0x014c,
			IMAGE_FILE_MACHINE_IA64 = 0x0200,
			IMAGE_FILE_MACHINE_AMD64 = 0x8664
		};

		enum class PECharacteristics : unsigned short 
		{
			IMAGE_FILE_RELOCS_STRIPPED = 0x1,
			IMAGE_FILE_EXECUTABLE_IMAGE,
			IMAGE_FILE_LINE_NUMS_STRIPPED = 0x4,
			IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x8,
			IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x10,
			IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x20,
			IMAGE_FILE_BYTES_REVERSED_LO = 0x80,
			IMAGE_FILE_32BIT_MACHINE = 0x100,
			IMAGE_FILE_DEBUG_STRIPPED = 0x200,
			IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x400,
			IMAGE_FILE_NET_RUN_FROM_SWAP = 0x800,
			IMAGE_FILE_SYSTEM = 0x1000,
			IMAGE_FILE_DLL = 0x2000,
			IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
			IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
		};
		
		enum class PEBitness : unsigned short 
		{
			IMAGE_NT_OPTIONAL_MAGIC_32 = 0x10B,
			IMAGE_NT_OPTIONAL_MAGIC_64 = 0x20b,
			IMAGE_ROM_OPTIONAL_MAGIC = 0x107
		};
	}
}

std::ostream& operator << (std::ostream& out, const peanalyzer::constants::MachineType value);