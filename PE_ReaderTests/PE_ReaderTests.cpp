#include "pch.h"
#include "CppUnitTest.h"
#include "../PE_Reader/include/PortableExecutableAnalyzer.h"
#include "../PE_Reader/include/constants.h"
#include "../PE_Reader/include/util.h"
#include "../PE_Reader/include/ImageHeaders.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Microsoft 
{
	namespace VisualStudio 
	{
		namespace CppUnitTestFramework
		{
			template<> static std::wstring ToString<uint16_t>(const uint16_t& ui)
			{
				return std::to_wstring(ui);
			};
		}
	}
}
namespace PEReaderTests
{
	TEST_CLASS(PEReaderTests)
	{
	public:
		TEST_METHOD(PEReaderExpectedOutputsMatch)
		{
			std::string path = "C:\\Users\\bryto\\source\\repos\\PE_Reader\\PE_ReaderTests\\TestFiles\\HikeFinderGis.exe";
			PortableExecutableAnalyzer pe(path);

			auto &file_header = pe.GetFileHeader();
			auto &optional_header = pe.GetOptionalHeader();
			auto &section_headers = pe.GetSectionHeaders();

			Assert::AreEqual((uint16_t)0x8664, (uint16_t)file_header.Machine);
			Assert::AreEqual((uint16_t)7, file_header.NumberOfSections);
		}
	};
}
