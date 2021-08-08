/*
	MIT License

	Copyright (c) 2020 xerox

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/


#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <string>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")
using nt_load_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);
using nt_unload_driver_t = NTSTATUS(__fastcall*)(PUNICODE_STRING);

namespace driver
{
	namespace util
	{
		inline bool delete_service_entry(const std::string& service_name)
		{
			HKEY reg_handle;
			static const std::string reg_key("System\\CurrentControlSet\\Services\\");

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			return ERROR_SUCCESS == RegDeleteKeyA(reg_handle, service_name.data()) && ERROR_SUCCESS == RegCloseKey(reg_handle);;
		}

		inline bool create_service_entry(const std::string& drv_path, const std::string& service_name)
		{
			HKEY reg_handle;
			std::string reg_key("System\\CurrentControlSet\\Services\\");
			reg_key += service_name;

			auto result = RegCreateKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set type to 1 (kernel)
			//
			constexpr std::uint8_t type_value = 1;
			result = RegSetValueExA(
				reg_handle,
				"Type",
				NULL,
				REG_DWORD,
				&type_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set error control to 3
			//
			constexpr std::uint8_t error_control_value = 3;
			result = RegSetValueExA(
				reg_handle,
				"ErrorControl",
				NULL,
				REG_DWORD,
				&error_control_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set start to 3
			//
			constexpr std::uint8_t start_value = 3;
			result = RegSetValueExA(
				reg_handle,
				"Start",
				NULL,
				REG_DWORD,
				&start_value,
				4u
			);

			if (result != ERROR_SUCCESS)
				return false;

			//
			// set image path to the driver on disk
			//
			result = RegSetValueExA(
				reg_handle,
				"ImagePath",
				NULL,
				REG_SZ,
				(std::uint8_t*)drv_path.c_str(),
				drv_path.size()
			);

			if (result != ERROR_SUCCESS)
				return false;

			return ERROR_SUCCESS == RegCloseKey(reg_handle);
		}

		// this function was coded by paracord: https://githacks.org/snippets/4#L94 
		inline bool enable_privilege(const std::wstring& privilege_name)
		{
			HANDLE token_handle = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
				return false;

			LUID luid{};
			if (!LookupPrivilegeValueW(nullptr, privilege_name.data(), &luid))
				return false;

			TOKEN_PRIVILEGES token_state{};
			token_state.PrivilegeCount = 1;
			token_state.Privileges[0].Luid = luid;
			token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
				return false;

			CloseHandle(token_handle);
			return true;
		}

		inline std::string get_service_image_path(const std::string& service_name)
		{
			HKEY reg_handle;
			DWORD bytes_read;
			char image_path[0xFF];
			static const std::string reg_key("System\\CurrentControlSet\\Services\\");

			auto result = RegOpenKeyA(
				HKEY_LOCAL_MACHINE,
				reg_key.c_str(),
				&reg_handle
			);

			result = RegGetValueA(
				reg_handle,
				service_name.c_str(),
				"ImagePath",
				REG_SZ,
				NULL,
				image_path,
				&bytes_read
			);

			RegCloseKey(reg_handle);
			return std::string(image_path);
		}
	}

	inline bool load(const std::string& drv_path, const std::string& service_name)
	{
		if (!util::enable_privilege(L"SeLoadDriverPrivilege"))
			return false;

		if (!util::create_service_entry("\\??\\" + std::filesystem::absolute(std::filesystem::path(drv_path)).string(), service_name))
			return false;

		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		static const auto lp_nt_load_drv =
			::GetProcAddress(
				GetModuleHandleA("ntdll.dll"),
				"NtLoadDriver"
			);

		if (lp_nt_load_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);
			return ERROR_SUCCESS == reinterpret_cast<nt_load_driver_t>(lp_nt_load_drv)(&driver_reg_path_unicode);
		}
		return false;
	}

	inline std::tuple<bool, std::string> load(const std::vector<std::uint8_t>& drv_buffer)
	{
		static const auto random_file_name = [](std::size_t length) -> std::string
		{
			static const auto randchar = []() -> char
			{
				const char charset[] =
					"0123456789"
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz";
				const std::size_t max_index = (sizeof(charset) - 1);
				return charset[rand() % max_index];
			};
			std::string str(length, 0);
			std::generate_n(str.begin(), length, randchar);
			return str;
		};

		const auto service_name = random_file_name(16);
		const auto file_path = std::filesystem::temp_directory_path().string() + service_name;
		std::ofstream output_file(file_path.c_str(), std::ios::binary);

		output_file.write((char*)drv_buffer.data(), drv_buffer.size());
		output_file.close();

		return { load(file_path, service_name), service_name };
	}

	inline std::tuple<bool, std::string> load(const std::uint8_t* buffer, const std::size_t size)
	{
		std::vector<std::uint8_t> image(buffer, buffer + size);
		return load(image);
	}

	inline bool unload(const std::string& service_name)
	{
		std::string reg_path("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
		reg_path += service_name;

		static const auto lp_nt_unload_drv =
			::GetProcAddress(
				GetModuleHandleA("ntdll.dll"),
				"NtUnloadDriver"
			);

		if (lp_nt_unload_drv)
		{
			ANSI_STRING driver_rep_path_cstr;
			UNICODE_STRING driver_reg_path_unicode;

			RtlInitAnsiString(&driver_rep_path_cstr, reg_path.c_str());
			RtlAnsiStringToUnicodeString(&driver_reg_path_unicode, &driver_rep_path_cstr, true);

			const bool unload_drv = !reinterpret_cast<nt_unload_driver_t>(lp_nt_unload_drv)(&driver_reg_path_unicode);
			const auto image_path = std::filesystem::temp_directory_path().string() + service_name;
			const bool delete_reg = util::delete_service_entry(service_name);
			const bool delete_drv = std::filesystem::remove(image_path);
			return unload_drv && delete_reg && delete_drv;
		}
		return false;
	}
}
