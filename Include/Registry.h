#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <system_error>

class Registry {
public:
	// Constructors 
	Registry() = default;
	Registry(HKEY root, const std::wstring& subkey, REGSAM access);
	~Registry();
	
	// Manipulation
	void close() noexcept;
	bool open(HKEY root, const std::wstring& subkey, REGSAM access = KEY_READ);
	bool create(HKEY root, const std::wstring& subkey, REGSAM access = KEY_WRITE);


private:
	static std::error_code toErrorCode(LONG winerr) noexcept {
		return std::make_error_code(static_cast<std::errc>(winerr));
	}

private:
	HKEY m_key = nullptr;
	std::error_code m_lastErr = { };
};

