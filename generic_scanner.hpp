//
// Created by victor on 11/25/26.
//

#ifndef CROSS_PLATFORM_MEMORY_SCANNER_GENERIC_SCANNER_HPP
#define CROSS_PLATFORM_MEMORY_SCANNER_GENERIC_SCANNER_HPP

#include <algorithm>
#include <cstdint>
#include <format>
#include <iostream>
#include <print>
#include <ranges>
#include <string>
#include <type_traits>

#if defined(_WIN32)
    #include "windows_scanner.hpp"
#elif defined(__linux__)
    #include "linux_scanner.hpp"
#else
    #error "Unsupported platform"
#endif

template <typename T>
class GenericScanner {
    ProcHandler<T> p;

    GenericScanner() {
        auto procs = ProcessLister::GetAllProcesses();
        size_t max_length = 0;
        for (const std::string& name : std::views::values(procs))
            max_length = std::max(max_length, name.length());

        for (const auto& proc : procs) {
            std::string formatted_name = std::format("{:<{}}", proc.second, max_length);
            std::print("Name: {}   pid: {}\n", formatted_name, proc.first);
        }

        std::print("Select an open process by entering it's pid:\n>");
        Pid pid;
        std::cin >> pid;
        p = ProcHandler<T>(pid);
    }

public:
    static GenericScanner& get_scanner_instance() {
        static GenericScanner scanner;
        return scanner;
    }

    static T ReadValue() {
        if constexpr (std::is_same_v<T, char>
                   || std::is_same_v<T, signed char>
                   || std::is_same_v<T, unsigned char>) {
            char c{};
            std::cin >> c;
            return static_cast<T>(c);
        } else {
            T data{};
            std::cin >> std::dec >> data;
            return data;
        }
    }

    void Run() {
        bool run = true;
        while (run) {
            std::print("Select an action:\n"
                       "0: Find a value\n"
                       "1. Modify the value at the specified addres\n"
                       "2. Exit\n");
            int val;
            std::cin >> val;
            switch (val) {
                case 0: {
                    std::print("Enter desired value: ");
                    T data = ReadValue();
                    p.Scan(data);
                    break;
                }
                case 1: {
                    void* addr;
                    std::print("Enter the address you want to write at (hex): ");
                    std::cin >> std::hex >> addr;
                    std::print("Enter the new value: ");
                    T data = ReadValue();
                    try {
                        p.Write(addr, data);
                        std::print("Wrote value at {}\n", addr);
                    } catch (const std::exception& e) {
                        std::print("{}\n", e.what());
                    }
                    break;
                }
                case 2: {
                    run = false;
                    break;
                }
                default: {
                    std::print("Invalid action\n");
                    break;
                }
            }
        }
        std::cin.clear();
    }
};

enum class types {
    char8,
    uchar8,
    int16,
    uint16,
    int32,
    uint32,
    int64,
    uint64,
    float32,
    float64
};

inline std::string type_to_str(types t) {
    switch (t) {
        case types::char8: return "char8";
        case types::uchar8: return "uchar8";
        case types::int16: return "int16";
        case types::uint16: return "uint16";
        case types::int32: return "int32";
        case types::uint32: return "uint32";
        case types::int64: return "int64";
        case types::uint64: return "uint64";
        case types::float32: return "float32";
        case types::float64: return "float64";
    }
    return "int32";
}

class MemoryScanner {
    types wanted_type;

public:
    MemoryScanner() {
        std::print("Select value type:\n"
                   " 0: char8       1: uchar8\n"
                   " 2: int16       3: uint16\n"
                   " 4: int32       5: uint32\n"
                   " 6: int64       7: uint64\n"
                   " 8: float32     9: float64\n>");
        int t = 0;
        std::cin >> t;
        switch (t) {
            case 0: wanted_type = types::char8; break;
            case 1: wanted_type = types::uchar8; break;
            case 2: wanted_type = types::int16; break;
            case 3: wanted_type = types::uint16; break;
            case 4: wanted_type = types::int32; break;
            case 5: wanted_type = types::uint32; break;
            case 6: wanted_type = types::int64; break;
            case 7: wanted_type = types::uint64; break;
            case 8: wanted_type = types::float32; break;
            case 9: wanted_type = types::float64; break;
            default:wanted_type = types::int32; break;
        }
        std::cout << type_to_str(wanted_type) << std::endl;
    }

    void RunScanner() const{
        switch (wanted_type) {
            case types::char8: GenericScanner<char>::get_scanner_instance().Run(); break;
            case types::uchar8: GenericScanner<unsigned char>::get_scanner_instance().Run(); break;
            case types::int16: GenericScanner<int16_t>::get_scanner_instance().Run(); break;
            case types::uint16: GenericScanner<uint16_t>::get_scanner_instance().Run(); break;
            case types::int32: GenericScanner<int32_t>::get_scanner_instance().Run(); break;
            case types::uint32: GenericScanner<uint32_t>::get_scanner_instance().Run(); break;
            case types::int64: GenericScanner<int64_t>::get_scanner_instance().Run(); break;
            case types::uint64: GenericScanner<uint64_t>::get_scanner_instance().Run(); break;
            case types::float32: GenericScanner<float>::get_scanner_instance().Run(); break;
            case types::float64: GenericScanner<double>::get_scanner_instance().Run(); break;
            default: GenericScanner<int32_t>::get_scanner_instance().Run(); break;
        }
    }
};

#endif //CROSS_PLATFORM_MEMORY_SCANNER_GENERIC_SCANNER_HPP
