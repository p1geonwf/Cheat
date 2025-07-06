#pragma once

#include <Memory.h>

class Memory;

using NtSuspendProcess_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle);
using NtResumeProcess_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle);

namespace Process {
	// Searchers
	DWORD getProcessId(const std::string_view processName);

	// Display functions
	void dispAllProcesses();
	void dispAllWindowedProcesses();
	void dispAllModules(DWORD processId);

	// VirtualAllocEx wrapper
	uintptr_t allocateProcessMemory(HANDLE processHandle, size_t allocationSize);

	// Thread management
	HANDLE createThread(HANDLE processHandle, uintptr_t startAddress, uintptr_t parameter = 0);
	void deleteThread(HANDLE processHandle, HANDLE threadHandle, uintptr_t bufferPtr);
	bool suspendThread(HANDLE threadHandle);
	bool resumeThread(HANDLE threadHandle);

	// Process management
	bool createProcess(std::string exeName, std::string args = { });
	bool terminateProcessById(DWORD processId, UINT exitCode = 1);
	bool terminateProcessByName(const std::string_view processName, UINT exitCode = 1);
	bool suspendProcess(DWORD processId);
	bool resumeProcess(DWORD processId);

	// Helpers
	BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
};