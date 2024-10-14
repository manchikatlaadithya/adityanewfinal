#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <vector>
#include <cstdint>

using namespace std;

// Predefined Constants for SHA-256
const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
uint32_t H[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Right rotate function
inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 functions
inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t Sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t Sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// Padding function
vector<uint8_t> padMessage(const string &message) {
    uint64_t messageLen = message.size() * 8;
    vector<uint8_t> paddedMessage(message.begin(), message.end());

    // Add 1 bit (0x80 in hexadecimal is 10000000 in binary)
    paddedMessage.push_back(0x80);

    // Add 0 padding until the message is congruent to 448 mod 512 (56 bytes mod 64)
    while ((paddedMessage.size() % 64) != 56) {
        paddedMessage.push_back(0x00);
    }

    // Append the original length in bits as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        paddedMessage.push_back((messageLen >> (i * 8)) & 0xFF);
    }

    return paddedMessage;
}

// Process the message in 512-bit (64-byte) chunks
void processChunk(const vector<uint8_t> &chunk) {
    uint32_t W[64];

    // Break chunk into sixteen 32-bit words
    for (int i = 0; i < 16; ++i) {
        W[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) | (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
    }

    // Extend the first 16 words into the remaining 48 words
    for (int i = 16; i < 64; ++i) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    // Initialize working variables
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

    // Main compression loop
    for (int i = 0; i < 64; ++i) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Add the compressed chunk to the current hash value
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

// Main function to compute SHA-256 hash
string sha256(const string &message) {
    // Step 1: Padding
    vector<uint8_t> paddedMessage = padMessage(message);

    // Step 2: Process each 512-bit chunk
    for (size_t i = 0; i < paddedMessage.size(); i += 64) {
        vector<uint8_t> chunk(paddedMessage.begin() + i, paddedMessage.begin() + i + 64);
        processChunk(chunk);
    }

    // Step 3: Produce final hash
    stringstream hash;
    for (int i = 0; i < 8; ++i) {
        hash << hex << setw(8) << setfill('0') << H[i];
    }

    return hash.str();
}

// Function to read a file into a string
string readFile(const string &fileName) {
    ifstream file(fileName);
    if (!file.is_open()) {
        cerr << "Unable to open file: " << fileName << endl;
        exit(1);
    }

    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    // File input (use the predefined file name)
    string fileName = "adityanew.txt";
    string fileContent = readFile(fileName);

    // Compute the SHA-256 hash
    string hash = sha256(fileContent);

    // Output the result
    cout << "SHA-256 Hash: " << hash << endl;

    return 0;
}
