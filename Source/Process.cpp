#include <Process.h>

DWORD Process::getProcessId(const std::string_view processName) {
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
		return 0;
	}

	DWORD pid = 0;
	if (Process32First(snapShot, &entry)) {
		do {
			if (CompareStrings(processName, entry.szExeFile)) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(snapShot, &entry));
	}

	CloseHandle(snapShot);
	if (pid == 0) {
		LOG_TO(Console)(Error,
			std::format(
				"Process {} not found!",
				processName
			)
		);
	}
	return pid;
}

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

bool Process::suspendThread(HANDLE threadHandle) {
	if (threadHandle == nullptr) {
		LOG_TO_Console(Error, "suspendThread(): invalid thread handle");
		return false;
	}

	DWORD prevCount = SuspendThread(threadHandle);
	if (prevCount == static_cast<DWORD>(-1)) {
		LOG_TO_Console(Error,
			std::format(
				"SuspendThread(): failed, Error code: {}",
				GetLastError()
			)
		);
		return false;
	}
	LOG_TO_Console(Info,
		std::format(
			"Thread suspended, Previous suspend count: {}",
			prevCount
		)
	);
	return true;
}

bool Process::resumeThread(HANDLE threadHandle) {
	if (threadHandle == nullptr) {
		LOG_TO_Console(Error, "resumeThread(): invalid thread handle");
		return false;
	}

	DWORD prevCount = ResumeThread(threadHandle);
	if (prevCount == static_cast<DWORD>(-1)) {
		LOG_TO_Console(Error,
			std::format(
				"ResumeThread(): failed, Error code: {}",
				GetLastError()
			)
		);
		return false;
	}
	LOG_TO_Console(Info,
		std::format(
			"Thread resumed, Previous suspend count: {}",
			prevCount
		)
	);
	return true;
}

bool Process::createProcess(std::string exeName, std::string args) {
	PROCESS_INFORMATION pi = { };
	STARTUPINFOA si = { };
	si.cb = sizeof(si);

	/* Windows itself will look for the Path of lpCommandLine's
	   first entry if lpApplicationName is nullptr */
	std::string cmdLine;
	if (args.empty()) {
		cmdLine = std::format("\"{}\"", exeName);
	}
	else {
		cmdLine = std::format("\"{}\" {}", exeName, args);
	}

	if (CreateProcessA(
		nullptr,
		cmdLine.data(),
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
				"Process \"{}\" created successfuly",
				exeName
			)
		);
		return true;
	}
	LOG_TO(Console)(Error,
		std::format(
			"Failed to create process. Error code: {}",
			GetLastError()
		)
	);
	return false;
}

bool Process::terminateProcessById(DWORD processId, UINT exitCode) {
	HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
	if (handle == nullptr) {
		LOG_TO(Console)(Error,
			std::format(
				"OpenProcess({}) for terminate failed, Error code: {}",
				processId,
				GetLastError()
			)
		);
		return false;
	}

	BOOL ok = TerminateProcess(handle, exitCode);
	CloseHandle(handle);

	if (!ok) {
		LOG_TO(Console)(Error,
			std::format(
				"TerminateProcess({}) failed, Error code: {}",
				processId,
				GetLastError()
			)
		);
		return false;
	}

	LOG_TO(Console)(Info,
		std::format(
			"Process {} killed (exit code {})",
			processId,
			exitCode
		)
	);
	return true;
}

bool Process::terminateProcessByName(const std::string_view processName, UINT exitCode) {
	DWORD pid = getProcessId(processName);
	if (pid == 0) {
		return false;
	}

	return terminateProcessById(pid, 1);
}

bool Process::suspendProcess(DWORD processId) {
	HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
	if (handle == nullptr) {
		LOG_TO(Console)(Error,
			std::format(
				"OpenProcess({}) failed, Error code: {}",
				processId,
				GetLastError()
			)
		);
		return false;
	}

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == nullptr) {
		LOG_TO(Console)(Error,
			std::format("GetModuleHandleA() failed, Error code: {}",
				GetLastError()
			)
		);
		CloseHandle(handle);
		return false;
	}

	auto func = reinterpret_cast<NtSuspendProcess_t>(GetProcAddress(ntdll, "NtSuspendProcess"));
	if (!func) {
		LOG_TO(Console)(Error,
			std::format(
				"GetProcAddress(NtSuspendProcess) failed, Error code: {}",
				GetLastError()
			)
		);
		CloseHandle(handle);
		return false;
	}

	NTSTATUS status = func(handle);
	CloseHandle(handle);

	if (!NT_SUCCESS(status)) {
		LOG_TO(Console)(Error,
			std::format(
				"NtSuspendProcess({}) failed: 0x{:08X}",
				processId,
				static_cast<unsigned>(status)
			)
		);
		return false;
	}

	LOG_TO(Console)(Info, std::format("Process {} suspended", processId));
	return true;
}

bool Process::resumeProcess(DWORD processId) {
	HANDLE handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
	if (handle == nullptr) {
		LOG_TO(Console)(Error,
			std::format(
				"OpenProcess({}) failed, Error code: {}",
				processId,
				GetLastError()
			)
		);
		return false;
	}

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == nullptr) {
		LOG_TO(Console)(Error,
			std::format("GetModuleHandleA() failed, Error code: {}",
				GetLastError()
			)
		);
		CloseHandle(handle);
		return false;
	}

	auto func = reinterpret_cast<NtResumeProcess_t>(GetProcAddress(ntdll, "NtResumeProcess"));
	if (!func) {
		LOG_TO(Console)(Error,
			std::format(
				"GetProcAddress(NtResumeProcess) failed, Error code: {}",
				GetLastError()
			)
		);
		CloseHandle(handle);
		return false;
	}

	NTSTATUS status = func(handle);
	CloseHandle(handle);

	if (!NT_SUCCESS(status)) {
		LOG_TO(Console)(Error,
			std::format(
				"NtResumeProcess({}) failed: 0x{:08X}",
				processId,
				static_cast<unsigned>(status)
			)
		);
		return false;
	}

	LOG_TO(Console)(Info, std::format("Process {} resumed", processId));
	return true;
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