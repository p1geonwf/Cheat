#include <Memory.h>

int main() {
	Process::createProcess("notepad.exe");

	// Find process
	/*
	const std::string_view processName = "Notepad.exe";
	Memory memory = { };
	memory.attachProcessByName(processName);
	*/

	// Process::suspendProcess(Process::getProcessId("Notepad.exe"));
	// Process::resumeProcess(Process::getProcessId("Notepad.exe"));
	// Process::terminateProcessById(Process::getProcessId("Notepad.exe"));
	// Process::terminateProcessByName("Notepad.exe");


	/*
	auto ret = memory.findAll<uint32_t>(1211);
	for (auto x : ret) {
		std::cout << std::hex << x.address << '\n';
	}
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

// Make a class to start processes
// Make class to edit registry
// Make a class for sockets and internet communication
// Make gui with either windows api or ImGui
// Make speedhack.dll which hooks functions 


// Make filesystem enumeration class use c++17 header file for that and link it to process.h
// Add threading by memory region