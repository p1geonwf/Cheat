#include <Memory.h>

int main() {
	Process::createProcess("notepad.exe");

	// Find process
	const std::string_view processName = "Notepad.exe";
	Memory memory = { };
	memory.attachProcessByName(processName);
	
	Process::suspendProcess(Process::getProcessId("Notepad.exe"));
	Process::resumeProcess(Process::getProcessId("Notepad.exe"));
	Process::terminateProcessById(Process::getProcessId("Notepad.exe"));
	Process::terminateProcessByName("Notepad.exe");

	/*
	std::string exePath = "C:\\Program Files\\Windows Media Player\\wmplayer.exe";
	std::string videoArg = "/play \"C:\\Users\\p1geo\\Desktop\\C++\\Malware and Hacks\\Cheat\\Output\\Debug\\lv_0_20210823164858.mp4\"";

	Process::createProcess(exePath, videoArg);
	*/
	/*
	while (true)
	{
		// Sleep		
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	*/
}

// Make a drop down menu that will show 2 tabs, one with windows and other with all processes
// check what can be const and constexpr,
// Something to poll for memory rescans of the selected addresses
// Make logger not display logs that are of lower levels then instantiated
// Make logs more descriptive check resumeThread

// Make class to edit registry
// Make a class for sockets and internet communication
// Make gui with either windows api or ImGui
// Make speedhack.dll which hooks functions 


// Make filesystem enumeration class use c++17 header file for that and link it to process.h
// Add threading by memory region


// Make registry class with the ability to use cmd to dispatch reg edit calls
// Make TaskScheduler class to schedule malware with schtask on cmd and with win32
// Edit run and RunOnce registries 
// Make cmd class with singleton class structure and ability to dispatch commands

// Adjust the privilege	with RtlAdjustPrivilege or SetPrivilege