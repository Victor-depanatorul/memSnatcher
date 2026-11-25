#ifndef CROSS_PLATFORM_MEMORY_SCANNER_LINUX_SCANNER_HPP
#define CROSS_PLATFORM_MEMORY_SCANNER_LINUX_SCANNER_HPP

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <print>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/uio.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <vector>

using Pid = pid_t;
using ProcHandle = pid_t;

template <typename T>
class ProcHandler {
    static_assert(std::is_trivially_copyable_v<T>,
                  "ProcHandler<T> requires a trivially copyable T "
                  "(raw bytes are copied to/from the target process).");

    using m_byte = unsigned char;

    ProcHandle proc = -1;
    std::vector<m_byte*> mem_list;

public:
    ProcHandler() = default;

    explicit ProcHandler(Pid pid) : proc(pid) {
        if (proc <= 0 || kill(proc, 0) < 0) {
            throw std::system_error(errno, std::system_category(), "Invalid PID or insufficient permissions");
        }
    }

    ~ProcHandler() = default;

    ProcHandler(const ProcHandler&) = delete;
    ProcHandler& operator=(const ProcHandler&) = delete;

    ProcHandler(ProcHandler&&) noexcept = default;
    ProcHandler& operator=(ProcHandler&&) noexcept = default;

    T ReadAtAddr(const void* addr) const {
        T data{};

        iovec local = {&data, sizeof(T)};

        iovec remote = {const_cast<void*>(addr), sizeof(T)};

        ssize_t bytes_read = process_vm_readv(proc, &local, 1, &remote, 1, 0);

        if (bytes_read < 0) {
            throw std::system_error(errno, std::system_category(), "process_vm_readv failed");
        }
        if (static_cast<size_t>(bytes_read) != sizeof(T)) {
            throw std::runtime_error("Incomplete memory read");
        }

        return data;
    }

    bool TryRead(const void* addr, T& out) const {
        iovec local = {&out, sizeof(T)};

        iovec remote = {const_cast<void*>(addr), sizeof(T)};

        return process_vm_readv(proc, &local, 1, &remote, 1, 0)
               == static_cast<ssize_t>(sizeof(T));
    }

    void Write(const void* addr, const T& data) {
        iovec local = {const_cast<T*>(&data), sizeof(T)};

        iovec remote = {const_cast<void*>(addr), sizeof(T)};

        ssize_t bytes_written = process_vm_writev(proc, &local, 1, &remote, 1, 0);
        if (bytes_written < 0) {
            throw std::system_error(errno, std::system_category(), "process_vm_writev failed");
        }
        if (static_cast<size_t>(bytes_written) != sizeof(T)) {
            throw std::runtime_error("Incomplete memory write");
        }
    }

    void Scan(const T& desired_val) {
        if (mem_list.empty()) {
            std::ifstream file{"/proc/" + std::to_string(proc) + "/maps"};
            if (!file) {
                std::cerr << "Cannot open /proc/" << proc << "/maps\n";
                return;
            }
            std::string line;

            const size_t page = getpagesize();
            std::vector<m_byte> buffer(page + sizeof(T));

            while (std::getline(file, line)) {
                std::istringstream iss(line);
                std::string addr_range, perms, offset, dev, inode, pathname;
                if (!(iss >> addr_range >> perms >> offset >> dev >> inode)) {
                    continue;
                }
                std::getline(iss >> std::ws, pathname);

                if (perms.size() < 2 || perms[0] != 'r' || perms[1] != 'w') {
                    continue;
                }
                if (pathname == "[vvar]" || pathname == "[vsyscall]"
                    || pathname == "[vdso]") {
                    continue;
                }

                size_t dash = addr_range.find('-');
                if (dash == std::string::npos) {
                    continue;
                }

                uintptr_t start = std::stoull(addr_range.substr(0, dash), nullptr, 16);
                uintptr_t end = std::stoull(addr_range.substr(dash + 1), nullptr, 16);
                const size_t region_size = end - start;
                if (region_size < sizeof(T)) {
                    continue;
                }

                auto* region_base = reinterpret_cast<m_byte*>(start);

                for (size_t off = 0; off < region_size; off += page) {
                    size_t toRead = std::min<size_t>(page + sizeof(T) - 1,
                                                     region_size - off);
                    iovec local{buffer.data(), toRead};
                    iovec remote{region_base + off, toRead};
                    ssize_t bytesRead = process_vm_readv(proc, &local, 1,
                                                         &remote, 1, 0);
                    if (bytesRead < static_cast<ssize_t>(sizeof(T))) {
                        continue;
                    }
                    for (size_t i = 0;
                         i < page && i + sizeof(T) <= static_cast<size_t>(bytesRead);
                         ++i) {
                        T data;
                        std::memcpy(&data, buffer.data() + i, sizeof(T));
                        if (data == desired_val) {
                            m_byte* found = region_base + off + i;
                            std::print("FOUND VALUE {} AT ADDRESS {}\n",
                                       desired_val,
                                       static_cast<const void*>(found));
                            mem_list.push_back(found);
                        }
                    }
                }
            }
        }
        else {
            std::vector<m_byte*> new_mem_list;
            new_mem_list.reserve(mem_list.size());
            for (auto* addr : mem_list) {
                T data;
                if (TryRead(addr, data) && data == desired_val) {
                    std::print("FOUND VALUE {} AT ADDRESS {}\n",
                               desired_val, static_cast<const void*>(addr));
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
        std::error_code ec;
        std::filesystem::directory_iterator it("/proc", ec), end;

        for (; !ec && it != end; it.increment(ec)) {
            const std::string name = it->path().filename().string();
            if (name.empty() || !std::ranges::all_of(name, [](unsigned char c) {
                    return std::isdigit(c) != 0;
                })) {
                continue;
            }

            std::ifstream comm(it->path() / "comm");
            std::string exe;
            if (std::getline(comm, exe)) {
                map.emplace(static_cast<Pid>(std::stoi(name)), exe);
            }
        }
        return map;
    }
};

#endif