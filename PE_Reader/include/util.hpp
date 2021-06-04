#pragma once

template<typename T>
T peanalyzer::util::from_bytes(std::byte* bytes)
{
	size_t size = sizeof(T);
	T value = 0;
	for (int i = 0; i < size; i++)
	{
		value |= static_cast<T>(*(bytes + i)) << (8 * i);
	}
	return value;
}