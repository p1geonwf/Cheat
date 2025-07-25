#pragma once

#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <array>
#include <format>
#include <chrono>
#include <ctime>
#include <fstream>

enum class LogLevel { Info, Warning, Error };
enum class SinkId { Console, TextFile, GUI, _count };

class Logger {
public:
    using SinkFn = std::function<void(LogLevel level, std::string_view file, int line, std::string_view msg)>;

    static void addSink(SinkId id, SinkFn sink) {
        auto idx = static_cast<size_t>(id);
        s_sinks[idx] = std::move(sink);
    }

    static void setLevel(LogLevel level) noexcept {
        s_threshold = level;
    }

    static void logTo(SinkId who, LogLevel level, std::string_view file, int line, std::string_view msg) {
        if (static_cast<int>(level) < static_cast<int>(s_threshold))
            return;

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
    static constexpr std::string_view enumToString(LogLevel level) noexcept {
        switch (level) {
        case LogLevel::Info:    return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error:   return "ERROR";
        default:                return "UNKNOWN";
        }
    }

    static std::string currentTimeStamp() {
        using clock = std::chrono::system_clock;
        auto now = clock::now();
        auto tt = clock::to_time_t(now);
        std::tm bt;

        #ifdef _WIN32
        localtime_s(&bt, &tt);
        #else
        localtime_r(&tt, &bt);
        #endif

        char buf[20];
        std::strftime(buf, sizeof(buf), "%d/%m/%y %H:%M:%S", &bt);
        return buf;
    }

    static std::string format( LogLevel level, std::string_view file, int line, std::string_view msg) {
        return std::format("[{}] [{}] {}:{} - {}",
            currentTimeStamp(),
            enumToString(level),
            file,
            line,
            msg);
    }

private:
    struct Registrar {
        Registrar() {
            // Console 
            Logger::addSink(SinkId::Console,
                [](auto, auto, auto, std::string_view msg) {
                    std::cerr << msg << "\n";
                });

            // File
            static std::ofstream logfile("logs.txt", std::ios::app);
            Logger::addSink(SinkId::TextFile,
                [&](auto, auto, auto, std::string_view msg) {
                    logfile << msg << "\n";
                });

            // GUI
            Logger::addSink(SinkId::GUI,
                [&](auto, auto, auto, std::string_view msg) {
                    // Will implement it with ImGui later
                });
        }
    };

private:
    static inline std::array<SinkFn, static_cast<size_t>(SinkId::_count)> s_sinks = { };
    static inline Registrar s_registrar;
    static inline LogLevel s_threshold = LogLevel::Info;
};


#ifdef _MSC_VER
    #define __SHORT_FILE__ (strrchr(__FILE__,'\\') ? strrchr(__FILE__,'\\') + 1 : __FILE__)
#else
    #define __SHORT_FILE__ (strrchr(__FILE__,'/')  ? strrchr(__FILE__,'/')  + 1 : __FILE__)
#endif


#define LOG_TO(sink)  LOG_TO_##sink
#ifndef RELEASE
    #define LOG_TO_Console(level, msg)  \
    Logger::logTo(SinkId::Console,  LogLevel::level, __SHORT_FILE__, __LINE__, msg)

    #define LOG_TO_TextFile(level, msg) \
    Logger::logTo(SinkId::TextFile, LogLevel::level, __SHORT_FILE__, __LINE__, msg)

    #define LOG_TO_GUI(level, msg)      \
    Logger::logTo(SinkId::GUI,      LogLevel::level, __SHORT_FILE__, __LINE__, msg)
#else
    #define LOG_TO_Console(level, msg)
    #define LOG_TO_TextFile(level, msg)
    #define LOG_TO_GUI(level, msg)
#endif

/*
* Examples:
* 
* LOG_TO(Console)(Info, "Info log to console");
* LOG_TO(TextFile)(Warning, "Warning log to text file");
* LOG_TO(GUI)(Error, "Error log to GUI");
* 
* For full file path use __FILE__
* 
*/ 