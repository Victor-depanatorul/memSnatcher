#ifndef MEMSNATCHER_PROC_HANDLER_HPP
#define MEMSNATCHER_PROC_HANDLER_HPP

#include <stdexcept>
#include <string>
#include <vector>
#include <format>
#include <print>
#include <iostream>
#include <type_traits>
#include <unordered_map>
#include <ranges>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <tlhelp32.h>


using ProcHandle = HANDLE;


template <typename T>
class ProcHandler {
    static_assert(std::is_trivially_copyable_v<T>,
                  "ProcHandler<T> requires a trivially copyable T "
                  "(raw bytes are copied to/from the target process).");

    using m_byte = unsigned char;

    ProcHandle proc;
    std::vector<m_byte*> mem_list;

public:
    ProcHandler() {proc = nullptr; mem_list.clear();}

    explicit ProcHandler(DWORD pid) {
        proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (proc == nullptr) {
            throw std::runtime_error(
                std::format("Cannot open process (code of error: {}). "
                            "Try running as administrator.", GetLastError()));
        }
    }

    ~ProcHandler() {
        if (proc != nullptr) {
            CloseHandle(proc);
        }
    }

    ProcHandler(const ProcHandler&)            = delete;
    ProcHandler& operator=(const ProcHandler&) = delete;

    ProcHandler(ProcHandler&& other) noexcept
        : proc(other.proc), mem_list(std::move(other.mem_list)) {
        other.proc = nullptr;
    }
    ProcHandler& operator=(ProcHandler&& other) noexcept {
        if (this != &other) {
            if (proc != nullptr) CloseHandle(proc);
            proc           = other.proc;
            mem_list       = std::move(other.mem_list);
            other.proc     = nullptr;
        }
        return *this;
    }

    T ReadAtAddr(const void* addr) const {
        T data;
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(proc, addr, &data, sizeof(T), &bytesRead)
            || bytesRead != sizeof(T)) {
            throw std::runtime_error(
                std::format("Read error at {} (code {})", addr, GetLastError()));
        }
        return data;
    }

    bool TryRead(const void* addr, T& out) const {
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(proc, addr, &out, sizeof(T), &bytesRead)
               && bytesRead == sizeof(T);
    }

    void Write(void* addr, const T& data) {
        SIZE_T bytesWritten = 0;
        if (!WriteProcessMemory(proc, addr, &data, sizeof(T), &bytesWritten)
            || bytesWritten != sizeof(T)) {
            throw std::runtime_error(
                std::format("Write error at {} (code {})", addr, GetLastError()));
        }
    }

    void Scan(const T& desiredVal) {
        if (mem_list.empty()) {
            SYSTEM_INFO sys_info{};
            GetNativeSystemInfo(&sys_info);

            auto* min_addr = static_cast<m_byte*>(sys_info.lpMinimumApplicationAddress);
            auto* max_addr = static_cast<m_byte*>(sys_info.lpMaximumApplicationAddress);

            MEMORY_BASIC_INFORMATION mbi{};
            m_byte* curr = min_addr;

            while (curr < max_addr
                   && VirtualQueryEx(proc, curr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                auto* region_base = static_cast<m_byte*>(mbi.BaseAddress);
                const SIZE_T region_size = mbi.RegionSize;

                DWORD prot = mbi.Protect & 0xFF;
                bool writable = (prot == PAGE_READWRITE
                              || prot == PAGE_WRITECOPY
                              || prot == PAGE_EXECUTE_READWRITE
                              || prot == PAGE_EXECUTE_WRITECOPY);
                bool guarded = (mbi.Protect & PAGE_GUARD) != 0;
                bool readable = (mbi.State == MEM_COMMIT) && writable && !guarded;

                if (readable && region_size >= sizeof(T)) {
                    const SIZE_T page = sys_info.dwPageSize ? sys_info.dwPageSize
                                                            : 0x1000;

                    std::vector<m_byte> buffer(page + sizeof(T));
                    for (SIZE_T off = 0; off < region_size; off += page) {
                        SIZE_T toRead = std::min<SIZE_T>(page + sizeof(T) - 1,
                                                         region_size - off);
                        SIZE_T bytesRead = 0;
                        if (!ReadProcessMemory(proc, region_base + off,
                                               buffer.data(), toRead, &bytesRead)
                            || bytesRead < sizeof(T)) {
                            continue;
                        }
                        for (SIZE_T i = 0;
                             i < page && i + sizeof(T) <= bytesRead; ++i) {
                            T data;
                            std::memcpy(&data, buffer.data() + i, sizeof(T));
                            if (data == desiredVal) {
                                m_byte* found = region_base + off + i;
                                std::print("FOUND VALUE {} AT ADDRESS {}\n",
                                           desiredVal,
                                           static_cast<const void*>(found));
                                mem_list.push_back(found);
                            }
                        }
                    }
                }
                curr = region_base + region_size;
            }
        }
        else {
            std::vector<m_byte*> new_mem_list;
            new_mem_list.reserve(mem_list.size());
            for (auto* addr : mem_list) {
                T data;
                if (TryRead(addr, data) && data == desiredVal) {
                    std::print("FOUND VALUE {} AT ADDRESS {}\n",
                               desiredVal, static_cast<const void*>(addr));
                    new_mem_list.push_back(addr);
                }
            }
            mem_list = std::move(new_mem_list);
        }

        std::print("Matches: {}\n", mem_list.size());
    }

    [[nodiscard]] const std::vector<m_byte*>& Matches() const { return mem_list; }
};

template <typename T>
class GenericScanner {
    ProcHandler<T> p;

    static std::unordered_map<DWORD, std::string> GetAllProcesses() {
        std::unordered_map<DWORD, std::string> map;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return map;
        }

        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                map.emplace(pe32.th32ProcessID, pe32.szExeFile);
            } while (Process32Next(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return map;
    }

    GenericScanner() {
        auto procs = GetAllProcesses();
        size_t max_length = 0;
        for (const std::string& name : std::views::values(procs))
            max_length = std::max(max_length, name.length());

        for (const auto& proc : procs) {
            std::string formatted_name = std::format("{:<{}}", proc.second, max_length);
            std::print("Name: {}   pid: {}\n", formatted_name, proc.first);
        }

        std::print("Select an open process by entering it's pid:\n>");
        DWORD pid;
        std::cin >> pid;
        p = ProcHandler<T>(pid);
    }

public:
    static GenericScanner& get_scanner_instance() {
        static GenericScanner scanner;
        return scanner;
    }

    // Reads a value of type T from std::cin.
    // For 1-byte char types we read an actual character; for the other
    // (multi-byte) numeric types we read a decimal number.
    static T ReadValue() {
        if constexpr (std::is_same_v<T, char>
                   || std::is_same_v<T, signed char>
                   || std::is_same_v<T, unsigned char>) {
            char c{};
            std::cin >> c;            // reads a single character
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
#endif //MEMSNATCHER_PROC_HANDLER_HPP