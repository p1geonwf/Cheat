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

void Memory::dispAllProcesses() {
	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(PROCESSENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
		return;
	}

	if (Process32First(snapShot, &entry)) {
		do {
			std::wcout << entry.szExeFile << L" | id: " << entry.th32ProcessID << std::endl;
		} while (Process32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
}

void Memory::dispAllWindowedProcesses() {
	std::unordered_set<DWORD> windowedPids;
	EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&windowedPids));

	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(entry);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
		return;
	}

	if (Process32First(snapShot, &entry)) {
		do {
			if (windowedPids.count(entry.th32ProcessID)) {
				std::wcout << entry.szExeFile << L" | id: " << entry.th32ProcessID << std::endl;
			}
		} while (Process32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
}

void Memory::dispAllModules(DWORD processId) {
	MODULEENTRY32 entry = { };
	entry.dwSize = sizeof(MODULEENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapShot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
		return;
	}

	if (Module32First(snapShot, &entry)) {
		do {
			std::wcout << entry.szExePath << std::endl;
		} while (Module32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
}

bool Memory::attachProcess(const std::string_view processName) {
	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(PROCESSENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	if (Process32First(snapShot, &entry)) {
		do {
			if (CompareStrings(processName, entry.szExeFile)) {
				m_processId = entry.th32ProcessID;
				m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, m_processId);
				if (m_processHandle == NULL) {
					std::cerr << "Failed to open process " << m_processId << ". Error code: " << GetLastError() << std::endl;
				}
				break;
			}
		} while (Process32Next(snapShot, &entry));
	}
	if (m_processId == 0) {
		std::cerr << "Process " << processName << " not found!" << std::endl;
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
		std::cerr << "Failed to create snapshot. Error code: " << GetLastError() << std::endl;
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
		std::cerr << "getModuleAddress() for " << moduleName << " failed!" << "\n";
	}
	return result;
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

bool Memory::injectDLL(std::string_view dllPath) {
	uintptr_t remoteStr = allocateProcessMemory(dllPath.size() + 1);

	std::vector<char> pathBuf(dllPath.begin(), dllPath.end());
	pathBuf.push_back('\0');

	if (!bufferWrite(remoteStr, pathBuf)) {
		VirtualFreeEx(m_processHandle, reinterpret_cast<LPVOID>(remoteStr), 0, MEM_RELEASE);
		return EXIT_FAILURE;
	}

	// Read <kernel32.dll> address (It will alwayse be loaded by windows)
	HMODULE localKernel = GetModuleHandleA("kernel32.dll");
	__analysis_assume(localKernel != nullptr);
	FARPROC localLoadA = GetProcAddress(localKernel, "LoadLibraryA");
	if (localLoadA == 0) {
		std::cerr << "GetProcAddress for LoadLibraryA failed!\n";
		return EXIT_FAILURE;
	}

	HANDLE remoteThread = createThread(reinterpret_cast<uintptr_t>(localLoadA), remoteStr);
	WaitForSingleObject(remoteThread, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(remoteThread, &exitCode);

	CloseHandle(remoteThread);
	VirtualFreeEx(m_processHandle, reinterpret_cast<LPVOID>(remoteStr), 0, MEM_RELEASE);

	if (exitCode == 0) {
		std::cerr << "Remote LoadLibraryA failed!" << "\n\n";
		return EXIT_FAILURE;
	}
	std::cout << "Loaded " << dllPath << " successfully!" << "\n\n";
	return EXIT_SUCCESS;
}

uintptr_t Memory::allocateProcessMemory(size_t allocationSize) {
	LPVOID remoteBufferPointer = VirtualAllocEx(
		m_processHandle,
		nullptr,
		static_cast<SIZE_T>(allocationSize),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (remoteBufferPointer == nullptr) {
		std::cerr << "VirtualAllocEx failed. Error code: " << GetLastError() << std::endl;
	}
	return reinterpret_cast<uintptr_t>(remoteBufferPointer);
}

HANDLE Memory::createThread(uintptr_t startAddress, uintptr_t parameter) {
	HANDLE threadHandle = CreateRemoteThread(
		m_processHandle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(startAddress),
		reinterpret_cast<LPVOID>(parameter),
		0,
		nullptr
	);

	if (threadHandle == nullptr) {
		std::cerr << "CreateRemoteThread failed. Error code: " << GetLastError() << std::endl;
	}

	return threadHandle;
}

void Memory::deleteThread(HANDLE threadHandle, uintptr_t bufferPtr) {
	if (threadHandle) {
		WaitForSingleObject(threadHandle, INFINITE);
		CloseHandle(threadHandle);

		if (bufferPtr != 0) {
            if (!VirtualFreeEx(m_processHandle, reinterpret_cast<LPVOID>(bufferPtr), 0, MEM_RELEASE)) {
                std::cerr << "Failed to free memory. Error code: " << GetLastError() << std::endl;
            } else {
                std::cout << "Memory freed successfully." << std::endl;
            }
        }
	}
}

bool Memory::changeMemoryProtection(uintptr_t address, size_t size, DWORD newProtection, DWORD& oldProtection) {
	if (!VirtualProtectEx(
		m_processHandle,
		reinterpret_cast<LPVOID>(address),
		static_cast<SIZE_T>(size),
		newProtection,
		&oldProtection)
		) {
		std::cerr << "VirtualProtectEx failed. Error code: " << GetLastError() << std::endl;
		return false;
	}
	return true;
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
		std::cerr << "VirtualProtectEx restore failed. Error code: " << GetLastError() << std::endl;
		return false;
	}
	return true;
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
		regions.push_back({ mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect });
		addr = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return regions;
}

BOOL CALLBACK Memory::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	if (!IsWindowVisible(hwnd))
		return TRUE;  // skip invisible windows

	DWORD processId = 0;
	GetWindowThreadProcessId(hwnd, &processId);
	if (processId != 0) {
		auto windowedPids = reinterpret_cast<std::unordered_set<DWORD>*>(lParam);
		windowedPids->insert(processId);
	}
	return TRUE;
}

std::vector<uintptr_t> Memory::findAllBytes(const void* pattern, size_t length) const {
	std::vector<uintptr_t> results;
	auto bytePatt = static_cast<const uint8_t*>(pattern);
	auto searcher = std::boyer_moore_searcher(bytePatt, bytePatt + length);

	for (const auto& region : enumerateMemoryRegions()) {
		if (!(region.state & MEM_COMMIT)) continue;
		if (!(region.protect & MemProtect::readWrite)) continue;

		auto base = reinterpret_cast<uintptr_t>(region.baseAddress);
		auto size = region.regionSize;

		// Read the entire region in one go
		std::vector<uint8_t> buffer(size);
		SIZE_T bytesRead = 0;
		if (!::ReadProcessMemory(
			m_processHandle,
			reinterpret_cast<LPCVOID>(base),
			buffer.data(),
			size,
			&bytesRead
		) || bytesRead < length) {
			continue;  // Couldn’t read or too small to match
		}

		auto scanBegin = buffer.begin();
		auto scanEnd = buffer.begin() + bytesRead;

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