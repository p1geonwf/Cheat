#include <Memory.h>

Memory::~Memory() {
	if (m_processHandle != nullptr) {
		CloseHandle(m_processHandle);
	}
}

DWORD Memory::getProcessID() const {
	return m_processId;
}

HANDLE Memory::getProcessHandle() const {
	return m_processHandle;
}

void Memory::setProcessID(DWORD processId) {
	m_processId = processId;
}

void Memory::setProcessHandle(HANDLE processHandle) {
	m_processHandle = processHandle;
}

bool Memory::attachProcess(const std::string_view processName) {
	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(PROCESSENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		LOG_TO(Console)(Error,
			std::format(
				"Failed to create snapshot. Error code: {}",
				GetLastError()
			)
		);
		return EXIT_FAILURE;
	}
	if (Process32First(snapShot, &entry)) {
		do {
			if (CompareStrings(processName, entry.szExeFile)) {
				m_processId = entry.th32ProcessID;
				m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, m_processId);
				if (m_processHandle == NULL) {
					LOG_TO(Console)(Error,
						std::format(
							"Failed to open process {}. Error code: {}",
							m_processId,
							GetLastError()
						)
					);
				}
				break;
			}
		} while (Process32Next(snapShot, &entry));
	}
	if (m_processId == 0) {
		LOG_TO(Console)(Error,
			std::format(
				"Process {} not found!",
				processName
			)
		);
		return EXIT_FAILURE;
	}

	CloseHandle(snapShot);

	return EXIT_SUCCESS;
}

uintptr_t Memory::getModuleAddress(const std::string_view moduleName) {
	MODULEENTRY32 entry = { };
	entry.dwSize = sizeof(MODULEENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_processId);
	if (snapShot == INVALID_HANDLE_VALUE) {
		LOG_TO(Console)(Error,
			std::format(
				"Failed to create snapshot. Error code: {}",
				GetLastError()
			)
		);
		return 0;
	}

	uintptr_t result = 0;
	if (Module32First(snapShot, &entry)) {
		do {
			if (CompareStrings(moduleName, entry.szModule)) {
				CloseHandle(snapShot);
				return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
			}
		} while (Module32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
	if (!result) {
		LOG_TO(Console)(Error,
			std::format(
				"getModuleAddress(): Failed for {}",
				moduleName
			)
		);
	}
	return result;
}

bool Memory::injectDLL(std::string_view dllPath) {
	uintptr_t remoteStr = Process::allocateProcessMemory(m_processHandle, dllPath.size() + 1);

	std::vector<char> pathBuf(dllPath.begin(), dllPath.end());
	pathBuf.push_back('\0');

	if (bufferWrite(remoteStr, pathBuf)) {
		VirtualFreeEx(m_processHandle, reinterpret_cast<LPVOID>(remoteStr), 0, MEM_RELEASE);
		LOG_TO(Console)(Error, "injectDLL(): VirtualFreeEx failed!");
		return EXIT_FAILURE;
	}

	// Read <kernel32.dll> address (It will alwayse be loaded by windows)
	HMODULE localKernel = GetModuleHandleA("kernel32.dll");
	__analysis_assume(localKernel != nullptr);
	FARPROC localLoadA = GetProcAddress(localKernel, "LoadLibraryA");
	if (localLoadA == 0) {
		LOG_TO(Console)(Error, "injectDLL(): GetProcAddress for LoadLibraryA failed!");
		return EXIT_FAILURE;
	}

	HANDLE remoteThread = Process::createThread(m_processHandle, reinterpret_cast<uintptr_t>(localLoadA), remoteStr);
	WaitForSingleObject(remoteThread, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(remoteThread, &exitCode);

	CloseHandle(remoteThread);
	VirtualFreeEx(m_processHandle, reinterpret_cast<LPVOID>(remoteStr), 0, MEM_RELEASE);

	if (exitCode == 0) {
		LOG_TO(Console)(Error, "createThread(): Remote LoadLibraryA failed!");
		return EXIT_FAILURE;
	}
	LOG_TO(Console)(Info,
		std::format(
			"Loaded {} successfully",
			dllPath
		)
		);
	return EXIT_SUCCESS;
}

std::vector<SearchResult<std::string>> Memory::findAll(const std::string& s) const {
	auto raw = findAllBytes(s);
	std::vector<SearchResult<std::string>> results;
	results.reserve(raw.size());

	for (auto addr : raw) {
		// Read back the actual bytes into a local string
		std::string val;
		val.resize(s.size());
		SIZE_T bytesRead = 0;
		::ReadProcessMemory(
			m_processHandle,
			reinterpret_cast<LPCVOID>(addr),
			val.data(),
			val.size(),
			&bytesRead
		);

		results.push_back({ addr, val });
	}

	return results;
}

bool Memory::changeMemoryProtection(uintptr_t address, size_t size, DWORD newProtection, DWORD& oldProtection) {
	if (!VirtualProtectEx(
		m_processHandle,
		reinterpret_cast<LPVOID>(address),
		static_cast<SIZE_T>(size),
		newProtection,
		&oldProtection)
		) {
		LOG_TO(Console)(Error,
			std::format(
				"VirtualProtectEx failed. Error code: {}",
				GetLastError()
			)
		);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

bool Memory::restoreMemoryProtection(uintptr_t address, size_t size, DWORD originalProtection) {
	DWORD temp = { };
	if (!VirtualProtectEx(
		m_processHandle,
		reinterpret_cast<LPVOID>(address),
		static_cast<SIZE_T>(size),
		originalProtection,
		&temp)
		) {
		LOG_TO(Console)(Error,
			std::format(
				"VirtualProtectEx restore failed. Error code: {}",
				GetLastError()
			)
		);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}


/*********** Private Member Functions ************/

std::vector<MemoryRegion> Memory::enumerateMemoryRegions() const {
	std::vector<MemoryRegion> regions;

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	LPVOID addr = sysInfo.lpMinimumApplicationAddress;

	while (addr < sysInfo.lpMaximumApplicationAddress) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQueryEx(m_processHandle, addr, &mbi, sizeof(mbi)) == 0)
			break;
		regions.push_back({ mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type });
		addr = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return regions;
}

std::vector<uintptr_t> Memory::findAllBytes(const void* pattern, size_t length) const {
	std::vector<uintptr_t> results;
	auto bytePatt = static_cast<const uint8_t*>(pattern);
	auto searcher = std::boyer_moore_searcher(bytePatt, bytePatt + length);

	for (const auto& region : enumerateMemoryRegions()) {
		if (!(region.state & MEM_COMMIT)) continue;
		if (region.protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
		if (!(region.protect & MemProtect::readWrite)) continue;
		// if (region.type != MEM_PRIVATE) continue;

		auto base = reinterpret_cast<uintptr_t>(region.baseAddress);
		auto size = region.regionSize;

		auto buffer = bufferRead<uint8_t>(base, size);
		if (buffer.size() < length) continue;

		auto scanBegin = buffer.begin();
		auto scanEnd = buffer.end();

		while (true) {
			auto it = std::search(scanBegin, scanEnd, searcher);
			if (it == scanEnd)
				break;

			uintptr_t matchAddr = base + std::distance(buffer.begin(), it);
			results.push_back(matchAddr);

			scanBegin = it + 1;
		}
	}

	return results;
}