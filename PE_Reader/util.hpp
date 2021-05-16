#pragma once
template<size_t byte_count>
unsigned short peanalyzer::util::short_from_bytes(std::byte(&bytes)[byte_count], size_t offset)
{
	if (offset < byte_count && offset + 1 < byte_count)
		return (static_cast<unsigned short>(bytes[offset + 1]) << 8) | static_cast<unsigned short>(bytes[offset]);
	return 0;
}