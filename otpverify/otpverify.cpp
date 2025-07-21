#include <iostream>
#include <string>

// Helper macro for array size
#define ARRAYSIZE(x) (sizeof(x)/sizeof(x[0]))

int main(int argc, char* argv[]) {
    // Usage: otpverify.exe <mode> <otp>
    if (argc != 3) return 99; // Usage error

    std::string mode = argv[1];
    std::string input = argv[2];

    // Define valid OTPs for each mode
    const char* normalOtps[] = { "4ko@", "_4op", "(5)P", "-&4o", "p)0p" }; // 4-char
    const char* admin1Otps[] = { "123456789", "abcdefghi", "otpfirst1" };    // 9-char
    const char* admin2Otps[] = { "987654321", "jihgfedcba", "otpsecond" };   // 9-char

    // Choose list and required length
    const char** otpList = nullptr;
    size_t otpCount = 0;
    size_t requiredLen = 0;
    if (mode == "normal") {
        otpList = normalOtps;  otpCount = ARRAYSIZE(normalOtps);  requiredLen = 4;
    }
    else if (mode == "admin1") {
        otpList = admin1Otps;  otpCount = ARRAYSIZE(admin1Otps);  requiredLen = 9;
    }
    else if (mode == "admin2") {
        otpList = admin2Otps;  otpCount = ARRAYSIZE(admin2Otps);  requiredLen = 9;
    }
    else {
        return 99; // Invalid mode
    }

    if (input.length() != requiredLen)
        return 1; // Invalid length is also invalid OTP

    for (size_t i = 0; i < otpCount; ++i) {
        if (input == otpList[i])
            return 0; // SUCCESS
    }
    return 1; // INVALID
}
