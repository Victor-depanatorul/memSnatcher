#include "win_scanner.hpp"

int main() {
    try {
        MemoryScanner memory_scanner;
        memory_scanner.RunScanner();
    }
    catch (std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
}