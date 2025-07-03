// 1) Create a list of type names
std::vector<std::string> typeNames = {
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "float",
    "double",
    "string"
};

// 2) Map each type name to a dispatch lambda
std::unordered_map<std::string,
    std::function<std::vector<uintptr_t>(const std::string&)>>
    dispatchMap;

// assume you have a Memory instance named 'mem'
dispatchMap["uint16_t"] = [&mem](const std::string& raw) {
    uint16_t v = static_cast<uint16_t>(std::stoul(raw));
    return mem.findAll<uint16_t>(v);
    };
dispatchMap["uint32_t"] = [&mem](const std::string& raw) {
    uint32_t v = static_cast<uint32_t>(std::stoul(raw));
    return mem.findAll<uint32_t>(v);
    };
dispatchMap["uint64_t"] = [&mem](const std::string& raw) {
    uint64_t v = static_cast<uint64_t>(std::stoull(raw));
    return mem.findAll<uint64_t>(v);
    };
dispatchMap["float"] = [&mem](const std::string& raw) {
    float v = std::stof(raw);
    return mem.findAll<float>(v);
    };
dispatchMap["double"] = [&mem](const std::string& raw) {
    double v = std::stod(raw);
    return mem.findAll<double>(v);
    };
dispatchMap["string"] = [&mem](const std::string& raw) {
    return mem.findAll(raw);
    };

// 3) In your UI event handler:
std::string selectedType = /* from dropdown */;
std::string userInput = /* from input box */;

auto it = dispatchMap.find(selectedType);
if (it != dispatchMap.end()) {
    std::vector<uintptr_t> results = it->second(userInput);
    // display results...
}