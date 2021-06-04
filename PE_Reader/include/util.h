#pragma once
#include "peanalyzer.h"

namespace peanalyzer 
{
	namespace util
	{
		template<typename T> T from_bytes(std::byte* bytes);
		std::string from_bytes(std::vector<std::byte>& buffer, size_t offset, size_t number_of_bytes);
	}
}

#include "util.hpp"