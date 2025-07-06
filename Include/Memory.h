#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <iostream>
#include <Windows.h>
#include <shellapi.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <chrono>
#include <sal.h> 

#include <Logger.h>
#include <Process.h>

namespace MemProtect {
	inline constexpr DWORD readWrite = PAGE_READWRITE;
	inline constexpr DWORD readOnly = PAGE_READONLY;
	inline constexpr DWORD execRead = PAGE_EXECUTE_READ;
	inline constexpr DWORD writeCopy = PAGE_WRITECOPY;
	inline constexpr DWORD fullScan = readWrite | readOnly | execRead | writeCopy;
}

inline bool CompareStrings(const std::string_view moduleName, const wchar_t* moduleNameToCompare) {
	std::wstring w;
	w.reserve(moduleName.size());
	for (unsigned char c : moduleName)
		w.push_back(static_cast<wchar_t>(c));

	return _wcsicmp(w.c_str(), moduleNameToCompare) == 0;
}

struct MemoryRegion {
	LPVOID baseAddress;
	SIZE_T regionSize;
	DWORD state;
	DWORD protect;
	DWORD type;
};

template<typename T> 
struct SearchResult {
	uintptr_t address;  
	T         value;
};

class Memory {
public:
	// Constructors 
	Memory() = default;
	~Memory();

	// Getters
	DWORD getProcessID() const;
	HANDLE getProcessHandle() const;

	// Setters
	void setProcessID(DWORD processId);
	void setProcessHandle(HANDLE processHandle);

	// Self explanatory
	bool attachProcess(const std::string_view processName);
	uintptr_t getModuleAddress(const std::string_view moduleName);

	// DLL injection
	bool injectDLL(std::string_view dllPath);

	// Memory reads
	template<typename T> std::vector<SearchResult<T>> findAll(const T& value) const;
	std::vector<SearchResult<std::string>> findAll(const std::string& s) const;

	// Memory writes
	template<typename T> void replaceValue(SearchResult<T>& oldState, T val);

	// Memory protection management
	bool changeMemoryProtection(uintptr_t address, size_t size, DWORD newProtection, DWORD& oldProtection);
	bool restoreMemoryProtection(uintptr_t address, size_t size, DWORD originalProtection);

	// Read/Write function wrappers 
	template <typename T> std::vector<T> bufferRead(const uintptr_t address, size_t count) const;
	template <typename T> std::optional<T> singleRead(const uintptr_t address) const;
	template <typename T> bool singleWrite(const uintptr_t address, const T& val);
	template <typename T> bool bufferWrite(const uintptr_t address, const std::vector<T>& buffer);

private:
	DWORD m_processId = 0;		      // Process id
	HANDLE m_processHandle = nullptr; // Process handle

	std::vector<MemoryRegion> enumerateMemoryRegions() const;
	template<typename T> std::vector<uintptr_t> findAllTypes(const T& value) const;
	std::vector<uintptr_t> findAllBytes(const void* pattern, size_t length) const;

	// overload for <pointer, length> container of bytes 
	template<typename C>
	auto findAllBytes(const C& c) const ->std::enable_if_t<
		std::is_same_v<typename C::value_type, char> ||
		std::is_same_v<typename C::value_type, uint8_t> ||
		std::is_same_v<typename C::value_type, std::byte>,
		std::vector<uintptr_t>> { return findAllBytes(c.data(), c.size() * sizeof(typename C::value_type)); }
};



/*************** Template implementations ***************/
template<typename T> std::vector<SearchResult<T>> Memory::findAll(const T& value) const {
	auto rawAddrs = findAllTypes(value);
	std::vector<SearchResult<T>> results;
	results.reserve(rawAddrs.size());

	for (auto addr : rawAddrs) {
		auto maybe = singleRead<T>(addr);
		if (maybe) {
			results.push_back({ addr, *maybe });
		}
	}

	return results;
}

template<typename T> std::vector<uintptr_t> Memory::findAllTypes(const T& value) const {
	static_assert(std::is_trivially_copyable_v<T>,
		"Only trivially copyable types");

	auto bytePatt = reinterpret_cast<const uint8_t*>(&value);
	size_t length = sizeof(T);
	size_t stride = alignof(T);

	std::vector<uintptr_t> results;
	std::vector<uint8_t> buffer;

	for (auto& region : enumerateMemoryRegions()) {
		if (!(region.state & MEM_COMMIT)) continue;
		if (region.protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
		if (!(region.protect & MemProtect::readWrite)) continue;
		// if (region.type != MEM_PRIVATE) continue;

		auto base = reinterpret_cast<uintptr_t>(region.baseAddress);
		auto size = region.regionSize;

		auto buffer = bufferRead<uint8_t>(base, size);
		if (buffer.size() < length) continue;

		// Walk in alignof(T) sized steps
		for (size_t offset = 0; offset + length <= buffer.size(); offset += stride) {
			if (std::memcmp(buffer.data() + offset, bytePatt, length) == 0){
				results.push_back(base + offset);
			}
		}
	}

	return results;
}

template<typename T> void Memory::replaceValue(SearchResult<T>& oldState, T val) {
	static_assert(std::is_trivially_copyable_v<T>,
		"replaceValue<T> only works on trivially copyable types");

	// Redundant check 
	if constexpr (std::is_arithmetic_v<T>) {
		if (val < std::numeric_limits<T>::lowest() || val > std::numeric_limits<T>::max()) {
			LOG_TO(Console)(Error, "UI didn't sanitize value properly");
			return;
		}
	}

	if (!singleWrite<T>(oldState.address, val)) {
		throw std::runtime_error("replaceValue: WriteProcessMemory failed");
	}
}

template <typename T>
std::optional<T> Memory::singleRead(const uintptr_t address) const {
	static_assert(std::is_trivially_copyable_v<T>,
		"Memory::read<T> requires trivially copyable T");

	SIZE_T bytesRead = { };
	T value = { };

	if (::ReadProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesRead)
		&& bytesRead == sizeof(T)) {
		return value;
	}
	LOG_TO(Console)(Error,
		std::format(
			"Failed to read memory at address {:#X}. Error code: {}",
			address,
			GetLastError()
		)
	);
	return std::nullopt;
}

template <typename T> bool Memory::singleWrite(const uintptr_t address, const T& val) {
	static_assert(std::is_trivially_copyable_v<T>,
		"singleWrite<T> requires a trivially copyable type");

	SIZE_T bytesWritten = { };

	if (::WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), &val, sizeof(T), &bytesWritten)
		&& bytesWritten == sizeof(T)) {
		return EXIT_SUCCESS;
	}
	LOG_TO(Console)(Error,
		std::format(
			"Failed to write memory at address {:#X}. Error code: {}",
			address,
			GetLastError()
		)
	);
	return EXIT_FAILURE;
}

template <typename T> std::vector<T> Memory::bufferRead(const uintptr_t address, size_t count) const {
	static_assert(std::is_trivially_copyable_v<T>,
		"singleWrite<T> requires a trivially copyable type");

	SIZE_T bytesRead = { };
	SIZE_T byteCount = count * sizeof(T);
	std::vector<T> buffer(count);

	if (!::ReadProcessMemory(m_processHandle, reinterpret_cast<LPCVOID>(address), buffer.data(), byteCount, &bytesRead)
		|| bytesRead < sizeof(T)) {
		LOG_TO(Console)(Error,
			std::format(
				"Failed to read buffer at address {:#X}. Error code: {}",
				address,
				GetLastError()
			)
		);
		return { };
	}

	buffer.resize(bytesRead / sizeof(T));
	return buffer;
}

template <typename T> bool Memory::bufferWrite(const uintptr_t address, const std::vector<T>& buffer) {
	static_assert(std::is_trivially_copyable_v<T>,
		"singleWrite<T> requires a trivially copyable type");

	SIZE_T bytesWritten = { };
	SIZE_T byteCount = buffer.size() * sizeof(T);

	if (::WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), buffer.data(), byteCount, &bytesWritten)
		&& bytesWritten == byteCount) {
		return EXIT_SUCCESS;
	}
	LOG_TO(Console)(Error,
		std::format(
			"Failed to write buffer at address {:#X}. Error code: {}",
			address,
			GetLastError()
		)
	);
	return EXIT_FAILURE;
}