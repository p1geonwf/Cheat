#pragma once

#include <unordered_set>
#include <thread>

#include <Memory.h>
// #include <Logger.h>

namespace Process {
	// Display functions
	void dispAllProcesses();
	void dispAllWindowedProcesses();
	void dispAllModules(DWORD processId);

	// VirtualAllocEx wrapper
	uintptr_t allocateProcessMemory(HANDLE processHandle, size_t allocationSize);

	// Thread management
	HANDLE createThread(HANDLE processHandle, uintptr_t startAddress, uintptr_t parameter = 0);
	void deleteThread(HANDLE processHandle, HANDLE threadHandle, uintptr_t bufferPtr);

	// Process management
	bool createProcess(std::string exePath);

	// Helpers
	BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
};

// TerminateProcess
// 
// SuspendThread
// ResumeThread
