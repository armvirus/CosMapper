#include "stdafx.hpp"

std::uint32_t mapDriver(std::vector<std::uint8_t>rawDriverImage)
{
	HookStruct request{};
	request.rawDataAddress = reinterpret_cast<std::uintptr_t>(rawDriverImage.data());
	request.rawDataSize = rawDriverImage.size();

	std::uint8_t mzSignature = *reinterpret_cast<std::uint8_t*>(request.rawDataAddress);
	if (mzSignature != 0x4d)
	{
		printf("invalid driver mz signature\n");
		return STATUS_INVALID_PARAMETER;
	}

	printf("[+] mz byte [0x%x]\n", mzSignature);
	printf("[+] size of driver [0x%x]\n", request.rawDataSize);
	printf("[+] driver read [%p]\n", request.rawDataAddress);

	void* requestPointer = &request;

	std::uint32_t status{};
	NtConvert(0, &requestPointer, &status, 0);

	RtlZeroMemory(reinterpret_cast<void*>(request.rawDataAddress), request.rawDataSize);

	return status;
}

int main(int argumentCount, char** argumentArray)
{
	if (argumentCount < 2 || std::filesystem::path(argumentArray[1]).extension().string().compare(".sys"))
	{
		printf("[-] usage: cosusermode.exe driver.sys\n");
		return -1;
	}

	if (!std::filesystem::exists(argumentArray[1])) 
	{
		printf("[-] driver [%s] does not exist\n", argumentArray[1]);
		return -1;
	}

	const auto& [status, service_name] = driver::load(signedMapperRaw, sizeof(signedMapperRaw));
	if (!status)
	{
		printf("[-] failed to load signed mapper\n");
		return -1;
	}

	printf("[+] loaded signed mapper [%s]\n", service_name.c_str());

	if (!Util::initializeDriverComm())
	{
		printf("[-] failed to initialize driver comm\n");
		return -1;
	}

	std::vector<uint8_t> rawDriverImage = { 0 };
	if (!Util::readFileToMemory(argumentArray[1], &rawDriverImage))
	{
		printf("[-] failed to read driver [%s]\n", argumentArray[1]);
		return -1;
	}

	printf("[+] mapped driver status [0x%x]\n", mapDriver(rawDriverImage));

	printf("[+] unloading signed mapper [0x%x]\n", !driver::unload(service_name));

	return 0;
}
