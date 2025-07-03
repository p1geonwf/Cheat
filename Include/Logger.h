#pragma once

#include <iostream>
#include <string_view>

enum class LogLevel { Info, Warning, Error };

class Logger {
public:
    static void log(LogLevel level,
        std::string_view file,
        int line,
        std::string_view msg)
    {
        const char* levelStr = nullptr;
        switch (level) {
        case LogLevel::Info:    levelStr = "INFO";    break;
        case LogLevel::Warning: levelStr = "WARNING"; break;
        case LogLevel::Error:   levelStr = "ERROR";   break;
        }

        std::cerr
            << "[" << levelStr << "] "
            << file << ":" << line << " — "
            << msg << "\n";
    }
};

// Convenience macros so you don’t have to type __FILE__ and __LINE__ every time
#define LOG_INFO(msg)    Logger::log(LogLevel::Info,    __FILE__, __LINE__, msg)
#define LOG_WARN(msg)    Logger::log(LogLevel::Warning, __FILE__, __LINE__, msg)
#define LOG_ERROR(msg)   Logger::log(LogLevel::Error,   __FILE__, __LINE__, msg)


// Fix all of this later