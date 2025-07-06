#include <Process.h>

void Process::dispAllProcesses() {
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
		return;
	}

	if (Process32First(snapShot, &entry)) {
		do {
			std::wcout << entry.szExeFile << L" | id: " << entry.th32ProcessID << std::endl;
		} while (Process32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
}

void Process::dispAllWindowedProcesses() {
	std::unordered_set<DWORD> windowedPids;
	EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&windowedPids));

	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(entry);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		LOG_TO(Console)(Error,
			std::format(
				"Failed to create snapshot. Error code: {}",
				GetLastError()
			)
		);
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

void Process::dispAllModules(DWORD processId) {
	MODULEENTRY32 entry = { };
	entry.dwSize = sizeof(MODULEENTRY32);

	const HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (snapShot == INVALID_HANDLE_VALUE) {
		LOG_TO(Console)(Error,
			std::format(
				"Failed to create snapshot. Error code: {}",
				GetLastError()
			)
		);
		return;
	}

	if (Module32First(snapShot, &entry)) {
		do {
			std::wcout << entry.szExePath << std::endl;
		} while (Module32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
}

uintptr_t Process::allocateProcessMemory(HANDLE processHandle, size_t allocationSize) {
	LPVOID remoteBufferPointer = VirtualAllocEx(
		processHandle,
		nullptr,
		static_cast<SIZE_T>(allocationSize),
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (remoteBufferPointer == nullptr) {
		LOG_TO(Console)(Error,
			std::format(
				"VirtualAllocEx failed. Error code: {}",
				GetLastError()
			)
			);
	}
	return reinterpret_cast<uintptr_t>(remoteBufferPointer);
}

HANDLE Process::createThread(HANDLE processHandle, uintptr_t startAddress, uintptr_t parameter) {
	HANDLE threadHandle = CreateRemoteThread(
		processHandle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(startAddress),
		reinterpret_cast<LPVOID>(parameter),
		0,
		nullptr
	);

	if (threadHandle == nullptr) {
		LOG_TO(Console)(Error,
			std::format(
				"CreateRemoteThread failed. Error code: {}",
				GetLastError()
			)
		);
	}

	return threadHandle;
}

void Process::deleteThread(HANDLE processHandle, HANDLE threadHandle, uintptr_t bufferPtr) {
	if (threadHandle) {
		WaitForSingleObject(threadHandle, INFINITE);
		CloseHandle(threadHandle);

		if (bufferPtr != 0) {
			if (!VirtualFreeEx(processHandle, reinterpret_cast<LPVOID>(bufferPtr), 0, MEM_RELEASE)) {
				LOG_TO(Console)(Error,
					std::format(
						"Failed to free memory. Error code: {}",
						GetLastError()
					)
				);
			}
			else {
				LOG_TO(Console)(Info, "deleteThread(): Memory freed successfully.");
			}
		}
	}
}

bool Process::createProcess(std::string exePath) {
	PROCESS_INFORMATION pi = { };
	STARTUPINFOA si = { };
	si.cb = sizeof(si);

	if (CreateProcessA(
		nullptr,
		exePath.data(),
		nullptr,
		nullptr,
		FALSE,
		0,
		nullptr,
		nullptr,
		&si,
		&pi
	)) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		LOG_TO(Console)(Info,
			std::format(
				"Process {} created successfuly",
				exePath
			)
		);
		return EXIT_SUCCESS;
	}
	LOG_TO(Console)(Error,
		std::format(
			"Failed to create process. Error code: {}",
			GetLastError()
		)
	);
	return EXIT_FAILURE;
}

BOOL CALLBACK Process::EnumWindowsProc(HWND hwnd, LPARAM lParam) {
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