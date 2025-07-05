#include <Memory.h>



int main() {
	/*
	HINSTANCE result = ShellExecuteA(
		nullptr,
		"open",
		"notepad.exe",
		nullptr,
		nullptr,
		SW_SHOW
	);
	
	Sleep(1000);
	*/
	// Find process
	const std::string_view processName = "Notepad.exe";
	Memory memory = { };
	if (!memory.attachProcess(processName)) {
		std::cout << "Process " << processName << " found!" << "\n\n";
	}

	bool breakPoint = true;

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
// Change all false and trues to exit failure/success
// Add threading by memory region
// Apply readBuffer to string versions
// Make a class to start processes

// Goals:
// Modify the game speed of kingdom rush
// Use imGui to make the cheat table