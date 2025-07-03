#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <iostream>
#include <Windows.h>
#include <shellapi.h>
#include <TlHelp32.h>
#include <thread>
#include <string>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <functional>         
#include <iterator>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <chrono>
#include <sal.h> 

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

	// Static functions
	static void dispAllProcesses();
	static void dispAllWindowedProcesses();
	static void dispAllModules(DWORD processId);

	// Self explanatory
	bool attachProcess(const std::string_view processName);
	uintptr_t getModuleAddress(const std::string_view moduleName);

	// Memory lookup
	template<typename T> std::vector<SearchResult<T>> findAll(const T& value) const;
	std::vector<SearchResult<std::string>> findAll(const std::string& s) const;
	template<typename T> void replaceValue(SearchResult<T>& oldState, T val);

	// VirtualAllocEx wrapper
	uintptr_t allocateProcessMemory(size_t allocationSize);

	// DLL injection
	bool injectDLL(std::string_view dllPath);
	
	// Thread management
	HANDLE createThread(uintptr_t startAddress, uintptr_t parameter = 0);
	void deleteThread(HANDLE threadHandle, uintptr_t bufferPtr);

	// Memory protection management
	bool changeMemoryProtection(uintptr_t address, size_t size, DWORD newProtection, DWORD& oldProtection);
	bool restoreMemoryProtection(uintptr_t address, size_t size, DWORD originalProtection);

	// Read/Write functions
	template <typename T> std::optional<T> read(const uintptr_t address) const;
	template <typename T> bool singleWrite(const uintptr_t address, const T& val);
	template <typename T> bool bufferWrite(const uintptr_t address, const std::vector<T>& buffer);

private:
	DWORD m_processId = 0;		      // Process id
	HANDLE m_processHandle = nullptr; // Process handle

	std::vector<MemoryRegion> enumerateMemoryRegions() const;
	static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
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



/* Template implementations */
template<typename T> std::vector<SearchResult<T>> Memory::findAll(const T& value) const {
	auto rawAddrs = findAllTypes(value);
	std::vector<SearchResult<T>> results;
	results.reserve(rawAddrs.size());

	for (auto addr : rawAddrs) {
		auto maybe = read<T>(addr);
		if (maybe) {
			results.push_back({ addr, *maybe });
		}
	}

	return results;
}

template<typename T> std::vector<uintptr_t> Memory::findAllTypes(const T& value) const {
	static_assert(std::is_trivially_copyable_v<T>,
		"Only trivially-copyable types");

	auto bytePatt = reinterpret_cast<const uint8_t*>(&value);
	size_t length = sizeof(T);
	size_t stride = alignof(T);

	std::vector<uintptr_t> results;
	std::vector<uint8_t>  buffer;

	for (auto& region : enumerateMemoryRegions()) {
		if (!(region.state & MEM_COMMIT)) continue;
		if (!(region.protect & MemProtect::readWrite)) continue;

		uintptr_t base = reinterpret_cast<uintptr_t>(region.baseAddress);
		size_t sz = region.regionSize;

		buffer.resize(sz);
		SIZE_T bytesRead = 0;
		if (!::ReadProcessMemory(m_processHandle,
			reinterpret_cast<LPCVOID>(base),
			buffer.data(),
			sz,
			&bytesRead)
			|| bytesRead < length)
		{
			continue;
		}

		// Walk in alignof(T) sized steps
		for (size_t offset = 0; offset + length <= bytesRead; offset += stride) {
			if (std::memcmp(buffer.data() + offset, bytePatt, length) == 0){
				results.push_back(base + offset);
			}
		}
	}

	return results;
}


template<typename T> void Memory::replaceValue(SearchResult<T>& oldState, T val) {
	static_assert(std::is_trivially_copyable_v<T>,
		"replaceValue<T> only works on trivially-copyable types");

	// Redundant check 
	if constexpr (std::is_arithmetic_v<T>) {
		if (val < std::numeric_limits<T>::lowest() || val > std::numeric_limits<T>::max()) {
			throw std::out_of_range("Seems like UI didn't sanitize value properly");
		}
	}

	if (!singleWrite<T>(oldState.address, val)) {
		throw std::runtime_error(
			"replaceValue: WriteProcessMemory failed");
	}
}

template <typename T>
std::optional<T> Memory::read(const uintptr_t address) const {
	static_assert(std::is_trivially_copyable_v<T>,
		"Memory::read<T> requires trivially copyable T");

	SIZE_T bytesRead = { };
	T value = { };

	if (::ReadProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesRead)
		&& bytesRead == sizeof(T)) {
		return value;
	}

	std::cerr << "Failed to read memory at address " << address << ". Error code: " << GetLastError() << std::endl;
	return std::nullopt;
}

template <typename T> bool Memory::singleWrite(const uintptr_t address, const T& val) {
	static_assert(std::is_trivially_copyable_v<T>,
		"singleWrite<T> requires a trivially-copyable type");

	SIZE_T bytesWritten = { };

	if (::WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), &val, sizeof(T), &bytesWritten)
		&& bytesWritten == sizeof(T)) {
		return true;
	}
	std::cerr << "Failed to write at address " << address << ". Error code: " << GetLastError() << std::endl;
	return false;
}


template <typename T> bool Memory::bufferWrite(const uintptr_t address, const std::vector<T>& buffer) {
	static_assert(std::is_trivially_copyable_v<T>,
		"singleWrite<T> requires a trivially-copyable type");

	SIZE_T bytesWritten = { };
	SIZE_T byteCount = buffer.size() * sizeof(T);

	if (::WriteProcessMemory(m_processHandle, reinterpret_cast<LPVOID>(address), buffer.data(), byteCount, &bytesWritten)
		&& bytesWritten == byteCount) {
		return true;
	}
	std::cerr << "Failed to write buffer at address " << address << ". Error code: " << GetLastError() << std::endl;
	return false;
}