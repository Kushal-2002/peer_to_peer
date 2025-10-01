#include <iostream>
#include <fstream>
#include <random>
#include <vector>

int main() {
    const std::string filename = "random_1GB.bin";
    const size_t file_size = 1ULL << 30; // 1 GB = 2^30 bytes
    const size_t buffer_size = 1 << 20;  // 1 MB buffer

    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile) {
        std::cerr << "Error: Could not open file for writing.\n";
        return 1;
    }

    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<unsigned int> dist(0, 255);

    std::vector<char> buffer(buffer_size);

    size_t bytes_written = 0;
    while (bytes_written < file_size) {
        for (size_t i = 0; i < buffer_size; ++i) {
            buffer[i] = static_cast<char>(dist(rng));
        }

        size_t chunk = std::min(buffer_size, file_size - bytes_written);
        outfile.write(buffer.data(), chunk);
        bytes_written += chunk;

        if (bytes_written % (100 * 1024 * 1024) == 0) {
            std::cout << "Written " << (bytes_written >> 20) << " MB...\n";
        }
    }

    outfile.close();
    std::cout << "File " << filename << " generated successfully (1 GB).\n";
    return 0;
}
