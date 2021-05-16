#include "util.h"
#include "constants.h"

unsigned short peanalyzer::util::short_from_bytes(std::byte upper_byte, std::byte lower_byte) 
{
	return (static_cast<unsigned short>(upper_byte) << 8) | static_cast<unsigned short>(lower_byte);
}

unsigned short peanalyzer::util::short_from_bytes(std::byte* bytes)
{
	return (static_cast<unsigned short>(*(bytes + 1)) << 8) | static_cast<unsigned short>(*bytes);
}

unsigned long peanalyzer::util::long_from_bytes(std::byte * bytes)
{
	return  (static_cast<unsigned long>(*(bytes + 3)) << 24) | 
			(static_cast<unsigned long>(*(bytes + 2)) << 16) |
			(static_cast<unsigned long>(*(bytes + 1)) << 8) | 
			(static_cast<unsigned long>(*bytes));
}

unsigned long long peanalyzer::util::u64_from_bytes(std::byte* bytes)
{
	return  (static_cast<unsigned long long>(*(bytes + 7)) << 56) |
			(static_cast<unsigned long long>(*(bytes + 6)) << 48) |
			(static_cast<unsigned long long>(*(bytes + 5)) << 40) |
			(static_cast<unsigned long long>(*(bytes + 4)) << 32) |
			(static_cast<unsigned long long>(*(bytes + 3)) << 24) |
			(static_cast<unsigned long long>(*(bytes + 2)) << 16) |
			(static_cast<unsigned long long>(*(bytes + 1)) << 8) |
			static_cast<unsigned long long>(*bytes);
}

std::ostream& operator << (std::ostream& out, const peanalyzer::constants::MachineType value)
{
	switch (value)
	{
		case peanalyzer::constants::MachineType::IMAGE_FILE_MACHINE_AMD64:
			out << "AMD64 (x64)";
			break;
		case peanalyzer::constants::MachineType::IMAGE_FILE_MACHINE_I386:
			out << "I386 (x86)";
			break;
		case peanalyzer::constants::MachineType::IMAGE_FILE_MACHINE_IA64:
			out << "Intel Itanium";
			break;
		default: break;
	}
	return out;
}