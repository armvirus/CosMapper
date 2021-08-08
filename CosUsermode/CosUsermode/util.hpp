#pragma once

inline PVOID(NTAPI* NtConvert)(PVOID, PVOID, PVOID, PVOID);

namespace Util
{
	inline bool readFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer)
	{
		std::ifstream file_ifstream(file_path, std::ios::binary);

		if (!file_ifstream)
			return false;

		out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
		file_ifstream.close();

		return true;
	}

	inline bool initializeDriverComm()
	{
		*reinterpret_cast<PVOID*>(&NtConvert) = GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");
		if (!NtConvert)
		{
			return false;
		}

		return true;
	}
}