// PE_Reader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <iomanip>
#include <ctime>
#include <string>
#include <sstream>
#include "PortableExecutableAnalyzer.h"

bool HasCharacteristic(unsigned short characteristics, peanalyzer::constants::PECharacteristics check)
{
    return (characteristics & static_cast<unsigned short>(check)) == static_cast<unsigned short>(check);
}

std::string PrintCharacteristics(unsigned short characteristics)
{
    using namespace peanalyzer::constants;
    std::stringstream characteristic_stream;
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_RELOCS_STRIPPED))
        characteristic_stream << "IMAGE_FILE_RELOCS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_EXECUTABLE_IMAGE))
        characteristic_stream << "IMAGE_FILE_EXECUTABLE_IMAGE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_LINE_NUMS_STRIPPED))
        characteristic_stream << "IMAGE_FILE_LINE_NUMS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_LOCAL_SYMS_STRIPPED))
        characteristic_stream << "IMAGE_FILE_LOCAL_SYMS_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_AGGRESIVE_WS_TRIM))
        characteristic_stream << "IMAGE_FILE_AGGRESIVE_WS_TRIM" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_LARGE_ADDRESS_AWARE))
        characteristic_stream << "IMAGE_FILE_LARGE_ADDRESS_AWARE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_BYTES_REVERSED_LO))
        characteristic_stream << "IMAGE_FILE_BYTES_REVERSED_LO" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_32BIT_MACHINE))
        characteristic_stream << "IMAGE_FILE_32BIT_MACHINE" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_DEBUG_STRIPPED))
        characteristic_stream << "IMAGE_FILE_DEBUG_STRIPPED" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP))
        characteristic_stream << "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_NET_RUN_FROM_SWAP))
        characteristic_stream << "IMAGE_FILE_NET_RUN_FROM_SWAP" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_SYSTEM))
        characteristic_stream << "IMAGE_FILE_SYSTEM" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_DLL))
        characteristic_stream << "IMAGE_FILE_DLL" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_UP_SYSTEM_ONLY))
        characteristic_stream << "IMAGE_FILE_UP_SYSTEM_ONLY" << "\n";
    if (HasCharacteristic(characteristics, PECharacteristics::IMAGE_FILE_BYTES_REVERSED_HI))
        characteristic_stream << "IMAGE_FILE_BYTES_REVERSED_HI" << "\n";
    return characteristic_stream.str();
}

int main()
{
    std::cout << "Reading in PE" << std::endl;
    std::string hikefinder_gis = "C:\\Users\\bryto\\source\\repos\\PE_Reader\\x64\\Debug\\HikeFinderGis.exe";
    PortableExecutableAnalyzer pe_analyzer(hikefinder_gis);
    std::size_t bytes_read = pe_analyzer.AnalyzeFile();
    const IMAGE_FILE_HEADER file_header = pe_analyzer.GetFileHeader();
    std::cout << "# of bytes read: " << bytes_read << std::endl;
    std::cout << "Machine type: " << file_header.Machine << std::endl;
    std::cout << "Number of sections: " << file_header.NumberOfSections << std::endl;
    std::time_t timestamp = file_header.TimeDateStamp;
    struct std::tm timeInfo;
    localtime_s(&timeInfo, &timestamp);
    std::cout << "Timestamp (linker creation time): " << std::put_time(&timeInfo, "%c") << std::endl;
    std::cout << "Pointer to symbol table: " << file_header.PointerToSymbolTable << std::endl;
    std::cout << "Number of symbols: " << file_header.NumberOfSymbols << std::endl;
    std::cout << "Size of optional header: " << file_header.SizeOfOptionalHeader << std::endl;
    std::cout << "Characteristics: " << "\n" << PrintCharacteristics(file_header.Characteristics) << std::endl;
    return 0;
}
