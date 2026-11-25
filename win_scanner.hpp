#ifndef CROSS_PLATFORM_MEMORY_SCANNER_WINDOWS_SCANNER_HPP
#define CROSS_PLATFORM_MEMORY_SCANNER_WINDOWS_SCANNER_HPP

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <print>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <tlhelp32.h>

using Pid = DWORD;
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

    explicit ProcHandler(Pid pid) {
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

class ProcessLister {
public:
    static std::unordered_map<Pid, std::string> GetAllProcesses() {
        std::unordered_map<Pid, std::string> map;
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
};

#endif