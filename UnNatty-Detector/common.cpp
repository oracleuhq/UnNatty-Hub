#define _CRT_SECURE_NO_WARNINGS
#include "common.h"
void logToFile(const std::string& filename, const std::string& content) {
    std::ofstream file(filename, std::ios::app);
    file << content << std::endl;
}

void printSeparator() {
    std::cout << BLUE << std::string(50, '=') << RESET << std::endl;
}

std::string fileTimeToString(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buffer[32];
    sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

std::string bytesToHexString(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (const auto& byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::string getCurrentTimestamp() {
    auto now = std::time(nullptr);
    auto* tm = std::localtime(&now);

    char buffer[32];
    sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        tm->tm_year + 1900,
        tm->tm_mon + 1,
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        tm->tm_sec);

    return std::string(buffer);
}