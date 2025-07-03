#pragma once

#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <format>
#include <chrono>
#include <ctime>

enum class LogLevel { Info, Warning, Error };
enum class SinkId { Console, TextFile, GUI, _count };

class Logger {
public:
    using SinkFn = std::function<void(
        LogLevel level,
        std::string_view file,
        int line,
        std::string_view msg
        )>;

    static void addSink(SinkId id, SinkFn sink) {
        auto idx = static_cast<size_t>(id);
        s_sinks[idx] = std::move(sink);
    }

    static void logTo(SinkId who, LogLevel level, std::string_view file, int line, std::string_view msg) {
        auto idx = static_cast<size_t>(who);
        auto& fn = s_sinks[idx];

        // To guard against non instantiated loggers (usually they are all instantiated)
        if (fn) fn(level, file, line, format(level, file, line, msg));
    }

    static void logToAll(LogLevel level, std::string_view file, int line, std::string_view msg) {
        for (size_t id = 0; id < static_cast<size_t>(SinkId::_count); ++id) {
            logTo(static_cast<SinkId>(id), level, file, line, msg);
        }
    }


private:
    static constexpr const char* enum_to_string(LogLevel level) noexcept {
        switch (level) {
        case LogLevel::Info:    return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error:   return "ERROR";
        default:                return "UNKNOWN";
        }
    }

    static std::string format(LogLevel level, std::string_view file, int line, std::string_view msg) {
        const char* levelStr = enum_to_string(level);

        return std::format(
            "[{}] {}:{} — {}",
            levelStr, file, line, msg
        );
    }

    static inline std::array<SinkFn, static_cast<size_t>(SinkId::_count)> s_sinks = { };
};

#define LOG_TO(sink)  LOG_TO_##sink

#define LOG_TO_Console(level, msg)   \
    Logger::logTo( SinkId::Console, LogLevel::level, __FILE__, __LINE__, msg)

#define LOG_TO_TextFile(level, msg)  \
    Logger::logTo(SinkId::TextFile, LogLevel::level, __FILE__, __LINE__, msg)

#define LOG_TO_GUI(level, msg)       \
    Logger::logTo(SinkId::GUI, LogLevel::level, __FILE__, __LINE__, msg)

/*
* Examples:
* 
* LOG_TO(Console)(Info, "Info log to console");
* LOG_TO(TextFile)(Warning, "Warning log to text file");
* LOG_TO(GUI)(Error, "Error log to GUI");
*/ 


// TODO:
// Instantiate every logger
// Add time support