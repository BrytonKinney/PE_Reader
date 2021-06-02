#include "util.h"
#include "constants.h"
#include "ImageHeaders.h"

std::string peanalyzer::util::from_bytes(std::vector<std::byte>& buffer, size_t offset, size_t number_of_bytes) 
{
	std::stringstream byte_string;
	for (size_t iter = offset; iter < offset + number_of_bytes; iter++)
	{
		byte_string << static_cast<char>(buffer.at(iter));
	}
	return byte_string.str();
}

std::ostream& operator << (std::ostream& out, const peanalyzer::constants::MachineType value)
{
	switch (value)
	{
		case peanalyzer::constants::MachineType::PE_IMAGE_FILE_MACHINE_AMD64:
			out << "AMD64 (x64)";
			break;
		case peanalyzer::constants::MachineType::PE_IMAGE_FILE_MACHINE_I386:
			out << "I386 (x86)";
			break;
		case peanalyzer::constants::MachineType::PE_IMAGE_FILE_MACHINE_IA64:
			out << "Intel Itanium";
			break;
		default: break;
	}
	return out;
}

std::ostream& operator << (std::ostream& out, const peanalyzer::constants::PEBitness value)
{
	switch (value)
	{
		case peanalyzer::constants::PEBitness::PE_IMAGE_NT_OPTIONAL_MAGIC_32:
			out << "32 Bit";
			break;
		case peanalyzer::constants::PEBitness::PE_IMAGE_NT_OPTIONAL_MAGIC_64:
			out << "64 Bit";
			break;
		case peanalyzer::constants::PEBitness::PE_IMAGE_ROM_OPTIONAL_MAGIC:
			out << "ROM";
			break;
		default: break;
	}
	return out;
}

std::ostream& operator << (std::ostream& out, const peanalyzer::constants::Subsystem value)
{
	using namespace peanalyzer::constants;
	switch (value)
	{
		case Subsystem::PE_IMAGE_SUBSYSTEM_UNKNOWN:
			out << "IMAGE_SUBSYSTEM_UNKNOWN";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_NATIVE:
			out << "IMAGE_SUBSYSTEM_NATIVE";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_WINDOWS_GUI:
			out << "IMAGE_SUBSYSTEM_WINDOWS_GUI";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_WINDOWS_CUI:
			out << "IMAGE_SUBSYSTEM_WINDOWS_CUI";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_OS2_CUI:
			out << "IMAGE_SUBSYSTEM_OS2_CUI";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_POSIX_CUI:
			out << "IMAGE_SUBSYSTEM_POSIX_CUI";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
			out << "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
			out << "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_EFI_APPLICATION:
			out << "IMAGE_SUBSYSTEM_EFI_APPLICATION";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
			out << "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
			out << "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_EFI_ROM:
			out << "IMAGE_SUBSYSTEM_EFI_ROM";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_XBOX:
			out << "IMAGE_SUBSYSTEM_XBOX";
			break;
		case Subsystem::PE_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
			out << "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
			break;
		default:
			break;
	}
	return out;
}