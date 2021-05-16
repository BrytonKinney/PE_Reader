#pragma once
#include "peanalyzer.h"

namespace peanalyzer 
{
	namespace util
	{
		unsigned short short_from_bytes(std::byte upper_byte, std::byte lower_byte);
		template<size_t byte_count>
		unsigned short short_from_bytes(std::byte (&bytes)[byte_count], size_t offset);
		unsigned short short_from_bytes(std::byte* bytes);
		unsigned long long_from_bytes(std::byte* bytes);
		unsigned long long u64_from_bytes(std::byte* bytes);
	}
}

#include "util.hpp"