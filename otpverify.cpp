#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 3) return 99; // Usage error

    std::string mode = argv[1];
    std::string otp = argv[2];

    // OTPs for demo; replace with your real secrets!
    const char* normalOtps[] = { "4ko@", "_4op", "(5)P", "-&4o", "p)0p" };
    const char* admin1Otps[] = { "123456789", "abcdefghi", "otpfirst1" };
    const char* admin2Otps[] = { "987654321", "jihgfedcba", "otpsecond" };

    const char** list = nullptr;
    size_t listSize = 0;
    size_t requiredLen = 0;

    if (mode == "normal") {
        list = normalOtps;
        listSize = sizeof(normalOtps) / sizeof(normalOtps[0]);
        requiredLen = 4;
    }
    else if (mode == "admin1") {
        list = admin1Otps;
        listSize = sizeof(admin1Otps) / sizeof(admin1Otps[0]);
        requiredLen = 9;
    }
    else if (mode == "admin2") {
        list = admin2Otps;
        listSize = sizeof(admin2Otps) / sizeof(admin2Otps[0]);
        requiredLen = 9;
    }
    else {
        return 99; // Invalid mode
    }

    if (otp.length() != requiredLen)
        return 1;

    for (size_t i = 0; i < listSize; ++i) {
        if (otp == list[i])
            return 0; // Valid
    }
    return 1; // Invalid value
}
