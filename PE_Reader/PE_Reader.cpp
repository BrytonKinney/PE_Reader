// PE_Reader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <ctime>
#include "PortableExecutableAnalyzer.h"

template <typename TIntegral, typename T>
bool HasCharacteristic(TIntegral characteristics, T check);
std::string PrintDllCharacteristics(unsigned short dll_characteristics);
std::string PrintCharacteristics(unsigned short characteristics);
std::string PrintDataDirectories(std::vector<peanalyzer::IMAGE_DATA_DIRECTORY>& directories);
std::string PrintSectionFlags(unsigned int flags);
void PrintFileHeader(peanalyzer::IMAGE_FILE_HEADER& file_header);
void PrintOptionalHeader(peanalyzer::IMAGE_OPTIONAL_HEADER& optional_header);
void PrintSectionHeaders(std::vector<peanalyzer::SECTION_HEADER>& section_headers);
std::tm& GetTime(uint32_t timestamp_value);

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Please specify the full path to the executable (e.g., PE_Reader.exe C:\\Users\\YourName\\Test.exe)" << std::endl;
        return -1;
    }
    std::string executable_path = argv[1];
    std::cout << "Reading in PE: " << executable_path << std::endl;
    PortableExecutableAnalyzer pe_analyzer(executable_path);
    std::size_t bytes_read = pe_analyzer.GetBytesRead();
    std::cout << "# of bytes read: " << bytes_read << std::endl;
    PrintFileHeader(pe_analyzer.GetFileHeader());
    if(pe_analyzer.GetFileHeader().SizeOfOptionalHeader > 0)
        PrintOptionalHeader(pe_analyzer.GetOptionalHeader());
    PrintSectionHeaders(pe_analyzer.GetSectionHeaders());
    std::cout << "\nImport Directory Table\n--------------------------\n";
    for (auto& idt : pe_analyzer.GetImportDirectoryTable())
    {
        std::cout << "Import Lookup Table RVA: " << std::hex << idt.ImportLookupTableRVA << std::dec << std::endl;
        auto timeInfo = GetTime(idt.Timestamp);
        std::cout << "Time/Date Stamp: " << std::put_time(&timeInfo, "%c") << "\n";
        std::cout << "Forwarder Chain: " << idt.ForwarderChain << std::endl;
        std::cout << "Import Name RVA: " << std::hex << idt.NameRVA << std::endl;
        std::cout << "Import Address Table RVA: " << idt.ImportAddressTableRVA << std::dec << "\n--------------------------" << std::endl;
    }
    std::ofstream text_fstream{ "text_section.txt", std::ios::trunc };
    pe_analyzer.WriteTextSectionDisassemblyToStream(text_fstream);
    text_fstream.close();
    std::filesystem::path text_section_path = std::filesystem::current_path().append("text_section.txt");
    std::cout << "Text disassembly written to " << text_section_path << std::endl;
    return 0;
}

template <typename TIntegral, typename T>
bool HasCharacteristic(TIntegral characteristics, T check)
{
    return (characteristics & static_cast<TIntegral>(check)) == static_cast<TIntegral>(check);
}

std::string PrintCharacteristics(unsigned short characteristics)
{
    using namespace peanalyzer::constants;
    std::stringstream characteristic_stream;
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_RELOCS_STRIPPED))
        characteristic_stream << "- IMAGE_FILE_RELOCS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_EXECUTABLE_IMAGE))
        characteristic_stream << "- IMAGE_FILE_EXECUTABLE_IMAGE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_LINE_NUMS_STRIPPED))
        characteristic_stream << "- IMAGE_FILE_LINE_NUMS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED))
        characteristic_stream << "- IMAGE_FILE_LOCAL_SYMS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_AGGRESIVE_WS_TRIM))
        characteristic_stream << "- IMAGE_FILE_AGGRESIVE_WS_TRIM" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_LARGE_ADDRESS_AWARE))
        characteristic_stream << "- IMAGE_FILE_LARGE_ADDRESS_AWARE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_BYTES_REVERSED_LO))
        characteristic_stream << "- IMAGE_FILE_BYTES_REVERSED_LO" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_32BIT_MACHINE))
        characteristic_stream << "- IMAGE_FILE_32BIT_MACHINE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_DEBUG_STRIPPED))
        characteristic_stream << "- IMAGE_FILE_DEBUG_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP))
        characteristic_stream << "- IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_NET_RUN_FROM_SWAP))
        characteristic_stream << "- IMAGE_FILE_NET_RUN_FROM_SWAP" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_SYSTEM))
        characteristic_stream << "- IMAGE_FILE_SYSTEM" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_DLL))
        characteristic_stream << "- IMAGE_FILE_DLL" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_UP_SYSTEM_ONLY))
        characteristic_stream << "- IMAGE_FILE_UP_SYSTEM_ONLY" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::PE_IMAGE_FILE_BYTES_REVERSED_HI))
        characteristic_stream << "- IMAGE_FILE_BYTES_REVERSED_HI" << "\n";
    return characteristic_stream.str();
}

std::string PrintDllCharacteristics(unsigned short dll_characteristics)
{
    using namespace peanalyzer::constants;
    std::stringstream characteristic_stream;
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_NX_COMPAT))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_NX_COMPAT" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_NO_ISOLATION" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_NO_SEH))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_NO_SEH" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_NO_BIND))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_NO_BIND" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_WDM_DRIVER" << "\n";
    if (HasCharacteristic(dll_characteristics, DllCharacteristics::PE_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE))
        characteristic_stream << "- IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE" << "\n";
    return characteristic_stream.str();
}

void PrintFileHeader(peanalyzer::IMAGE_FILE_HEADER& file_header)
{
    std::cout << "\nFILE HEADER\n--------------------------\n";
    std::cout << "Machine type: " << file_header.Machine << "\n";
    std::cout << "Number of sections: " << file_header.NumberOfSections << "\n";
    auto timeInfo = GetTime(file_header.TimeDateStamp);
    std::cout << "Timestamp (linker creation time): " << std::put_time(&timeInfo, "%c") << "\n";
    std::cout << "Pointer to symbol table: " << file_header.PointerToSymbolTable << "\n";
    std::cout << "Number of symbols: " << file_header.NumberOfSymbols << "\n";
    std::cout << "Size of optional header: " << file_header.SizeOfOptionalHeader << "\n";
    std::cout << "Characteristics:\n" << PrintCharacteristics(file_header.Characteristics) << "\n";
}

std::tm& GetTime(uint32_t timestamp_value)
{
    std::time_t timestamp = timestamp_value;
    std::tm timeInfo;
    localtime_s(&timeInfo, &timestamp);
    return timeInfo;
}

void PrintOptionalHeader(peanalyzer::IMAGE_OPTIONAL_HEADER& optional_header)
{
    std::cout << "OPTIONAL HEADER\n--------------------------\n";
    std::cout << "Magic Number (PE Bitness): " << optional_header.Magic << std::endl;
    std::cout << "Linker Version: " << static_cast<unsigned short>(optional_header.MajorLinkerVersion) << "." << static_cast<unsigned short>(optional_header.MinorLinkerVersion) << std::endl;
    std::cout << "Size of code: " << optional_header.SizeOfCode << " bytes" << std::endl;
    std::cout << "Size of initialized data: " << optional_header.SizeOfInitializedData << " bytes" << std::endl;
    std::cout << "Size of uninitialized data: " << optional_header.SizeOfUninitializedData << " bytes" << std::endl;
    std::cout << "Address of entry point: 0x" << std::hex << optional_header.AddressOfEntryPoint << std::endl;
    std::cout << "Base of code: 0x" << optional_header.BaseOfCode << std::endl;
    std::cout << "Base of data: 0x" << optional_header.BaseOfData << std::endl;
    std::cout << "Image base: 0x" << optional_header.ImageBase << std::endl << std::dec;
    std::cout << "Section alignment: " << optional_header.SectionAlignment << std::endl;
    std::cout << "File alignment: " << optional_header.FileAlignment << std::endl;
    std::cout << "OS version: " << optional_header.MajorOperatingSystemVersion << "." << optional_header.MinorOperatingSystemVersion << std::endl;
    std::cout << "Image Version: " << optional_header.MajorImageVersion << "." << optional_header.MinorImageVersion << std::endl;
    std::cout << "Subsystem Version: " << optional_header.MajorSubsystemVersion << "." << optional_header.MinorSubsystemVersion << std::endl;
    std::cout << "Win32 Version: " << optional_header.Win32VersionValue << std::endl;
    std::cout << "Size of image: " << optional_header.SizeOfImage << std::endl;
    std::cout << "Size of headers: " << optional_header.SizeOfHeaders << std::endl;
    std::cout << "Checksum: " << optional_header.CheckSum << std::endl;
    std::cout << "Subsystem: " << optional_header.Subsystem << std::endl;
    std::cout << "DLL Characteristics:\n" << PrintDllCharacteristics(optional_header.DllCharacteristics) << std::endl;
    std::cout << "Size of Stack Reserve: " << optional_header.SizeOfStackReserve << std::endl;
    std::cout << "Size of Stack Commit: " << optional_header.SizeOfStackCommit << std::endl;
    std::cout << "Size of Heap Reserve: " << optional_header.SizeOfHeapReserve << std::endl;
    std::cout << "Size of Heap Commit: " << optional_header.SizeOfHeapCommit << std::endl;
    std::cout << "Loader Flags: " << optional_header.LoaderFlags << std::endl;
    std::cout << "Number of RVA and Sizes: " << optional_header.NumberOfRvaAndSizes << std::endl;
    std::cout << PrintDataDirectories(optional_header.DataDirectory) << std::endl;
}

std::string PrintDataDirectories(std::vector<peanalyzer::IMAGE_DATA_DIRECTORY>& directories)
{
    std::stringstream characteristic_stream;
    characteristic_stream << "\nDATA DIRECTORIES\n--------------------------\n";
    for (unsigned int i = 0; i < directories.size(); i++)
    {
        characteristic_stream << peanalyzer::constants::DataDirectories[i] << "\n";
        characteristic_stream << "Address: 0x" << std::hex << directories.at(i).VirtualAddress << "\n";
        characteristic_stream << "Size: " << std::dec << directories.at(i).Size << "\n\n";
    }
    return characteristic_stream.str();
}

std::string PrintSectionFlags(unsigned int flags)
{
    using namespace peanalyzer::constants;
    std::stringstream characteristic_stream;
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_TYPE_NO_PAD))
        characteristic_stream << "- IMAGE_SCN_TYPE_NO_PAD" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_CNT_CODE))
        characteristic_stream << "- IMAGE_SCN_CNT_CODE" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_CNT_INITIALIZED_DATA))
        characteristic_stream << "- IMAGE_SCN_CNT_INITIALIZED_DATA" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_CNT_UNINITIALIZED_DATA))
        characteristic_stream << "- IMAGE_SCN_CNT_UNINITIALIZED_DATA" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_LNK_OTHER))
        characteristic_stream << "- IMAGE_SCN_LNK_OTHER" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_LNK_INFO))
        characteristic_stream << "- IMAGE_SCN_LNK_INFO" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_LNK_REMOVE))
        characteristic_stream << "- IMAGE_SCN_LNK_REMOVE" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_LNK_COMDAT))
        characteristic_stream << "- IMAGE_SCN_LNK_COMDAT" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_GPREL))
        characteristic_stream << "- IMAGE_SCN_GPREL" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_PURGEABLE))
        characteristic_stream << "- IMAGE_SCN_MEM_PURGEABLE" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_16BIT))
        characteristic_stream << "- IMAGE_SCN_MEM_16BIT" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_LOCKED))
        characteristic_stream << "- IMAGE_SCN_MEM_LOCKED" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_PRELOAD))
        characteristic_stream << "- IMAGE_SCN_MEM_PRELOAD" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_1BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_1BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_2BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_2BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_4BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_4BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_8BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_8BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_16BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_16BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_32BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_32BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_64BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_64BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_128BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_128BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_256BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_256BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_512BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_512BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_1024BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_1024BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_2048BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_2048BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_4096BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_4096BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_ALIGN_8192BYTES))
        characteristic_stream << "- IMAGE_SCN_ALIGN_8192BYTES" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_LNK_NRELOC_OVFL))
        characteristic_stream << "- IMAGE_SCN_LNK_NRELOC_OVFL" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_DISCARDABLE))
        characteristic_stream << "- IMAGE_SCN_MEM_DISCARDABLE" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_NOT_CACHED))
        characteristic_stream << "- IMAGE_SCN_MEM_NOT_CACHED" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_NOT_PAGED))
        characteristic_stream << "- IMAGE_SCN_MEM_NOT_PAGED" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_SHARED))
        characteristic_stream << "- IMAGE_SCN_MEM_SHARED" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_EXECUTE))
        characteristic_stream << "- IMAGE_SCN_MEM_EXECUTE" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_READ))
        characteristic_stream << "- IMAGE_SCN_MEM_READ" << "\n";
    if (HasCharacteristic(flags, SectionCharacteristics::PE_IMAGE_SCN_MEM_WRITE))
        characteristic_stream << "- IMAGE_SCN_MEM_WRITE" << "\n";
    return characteristic_stream.str();
}

void PrintSectionHeaders(std::vector<peanalyzer::SECTION_HEADER>& section_headers)
{
    std::cout << "SECTION HEADERS\n--------------------------\n";
    for (peanalyzer::SECTION_HEADER& section_header : section_headers)
    {
        std::cout << section_header.Name << "\n--------------------------\n";
        std::cout << "Virtual Size: " << section_header.VirtualSize << "\n";
        std::cout << "Virtual Address: 0x" << std::hex << section_header.VirtualAddress << "\n" << std::dec;
        std::cout << "Size of raw data: " << section_header.SizeOfRawData << "\n";
        std::cout << "Pointer to raw data: 0x" << std::hex << section_header.PointerToRawData << "\n";
        std::cout << "Pointer to relocations: 0x" << section_header.PointerToRelocations << "\n";
        std::cout << "Pointer to line numbers: 0x" << section_header.PointerToLineNumbers << "\n" << std::dec;
        std::cout << "Number of relocations: " << section_header.NumberOfRelocations << "\n";
        std::cout << "Number of line numbers: " << section_header.NumberOfLineNumbers << "\n";
        std::cout << "Section Flags: \n" << PrintSectionFlags(section_header.Characteristics) << "\n" << std::endl;
    }
}
