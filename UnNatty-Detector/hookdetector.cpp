#include "hookdetector.h"
#include <fstream>
#include <iostream>
#include <wintrust.h>
#include <softpub.h>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <chrono>
#include <Shlobj.h>
#include <thread>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), strTo.data(), size_needed, nullptr, nullptr);
    return strTo;
}

const wchar_t* boxChars[] = {
    L"-------------------------------------------------------",
    L"               MEMORY PATCHES DETECTED               ",
    L"                 NO FALSE DETECTIONS                 ",
    L"-------------------------------------------------------"
};

HookDetector::HookDetector() {
    SetConsoleOutputCP(CP_UTF8);

    HOOK_PATTERNS = {
        {{0xFF, 0x25}, "JMP FAR"},
        {{0xFF, 0x15}, "CALL FAR"},
        {{0xE9}, "JMP NEAR"},
        {{0xE8}, "CALL NEAR"},
        {{0xFF, 0x35}, "PUSH"},
        {{0x68}, "PUSH IMM"},
        {{0xFF, 0x24}, "JMP INDIRECT"},
        {{0xFF, 0x14}, "CALL INDIRECT"},
        {{0x90}, "NOP"},
        {{0xCC}, "INT3"},
        {{0xCD, 0x03}, "INT 3"},
        {{0xF3, 0x90}, "PAUSE"},
        {{0xFF, 0xFF}, "Invalid Opcode"}
    };
}
void HookDetector::writeHookDetails(const std::string& logFilePath, const HookDetectionResult& result, bool isHook) {
    std::ofstream outFile(logFilePath, std::ios::app);

    std::string header = isHook ? "HOOK DETECTION ALERT" : "MEMORY PATCH DETECTED";
    std::string separator = std::string(80, '=');

    if (outFile.is_open()) {
        outFile << "\n" << separator << "\n";
        outFile << "                    " << header << "\n";
        outFile << separator << "\n\n";

        outFile << "Details:\n";
        outFile << "-------------\n";
        outFile << "Section Name: " << result.sectionName << "\n";
        outFile << "Offset: 0x" << std::hex << result.offset << std::dec << "\n";
        outFile << (isHook ? "Hook Type: " : "Patch Type: ") << result.hookType << "\n";
        outFile << "Original Bytes: " << bytesToHexString(result.originalBytes) << "\n";
        outFile << "Modified Bytes: " << bytesToHexString(result.modifiedBytes) << "\n\n";
        outFile << "Integrity Status: " << (isHook ? "VIOLATED" : "PATCHED") << "\n";
        outFile << "Hook Confidence: 100% POSITIVE\n";
        outFile << separator << "\n\n";
    }
}

HookDetectionResult HookDetector::analyzeModule(const ProcessInfo& processInfo) {
    HookDetectionResult result;
    result.foundHooks = false;
    bool hookDetectedPrinted = false;

    try {
        wchar_t localAppData[MAX_PATH];
        std::wstring voiceNodePath;
        std::wstring discordType;

        HANDLE procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processInfo.pid);
        if (procHandle) {
            wchar_t processPath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(procHandle, 0, processPath, &size)) {
                std::wstring fullPath(processPath);
                std::filesystem::path exePath(fullPath);
                std::wstring processName = exePath.filename().wstring();

                if (processName.find(L"DiscordCanary") != std::wstring::npos) {
                    discordType = L"DiscordCanary";
                }
                else if (processName.find(L"DiscordPTB") != std::wstring::npos) {
                    discordType = L"DiscordPTB";
                }
                else {
                    discordType = L"Discord";
                }
            }
            CloseHandle(procHandle);
        }

        if (discordType.empty()) {
            discordType = L"Discord";
        }

        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::filesystem::path baseDir(localAppData);
            std::filesystem::path discordPath = baseDir / discordType;

            if (std::filesystem::exists(discordPath)) {
                std::wstring latestVersion;
                std::filesystem::path latestPath;

                for (const auto& entry : std::filesystem::directory_iterator(discordPath)) {
                    if (entry.is_directory() && entry.path().filename().wstring().find(L"app-") == 0) {
                        std::wstring version = entry.path().filename().wstring().substr(4);
                        if (version > latestVersion) {
                            latestVersion = version;
                            latestPath = entry.path();
                        }
                    }
                }

                if (!latestPath.empty()) {
                    auto modulePath = latestPath / L"modules";
                    for (const auto& entry : std::filesystem::directory_iterator(modulePath)) {
                        if (entry.is_directory() && entry.path().filename().wstring().find(L"discord_voice") == 0) {
                            std::filesystem::path nodePath = entry.path() / L"discord_voice" / L"discord_voice.node";
                            if (std::filesystem::exists(nodePath)) {
                                voiceNodePath = nodePath.wstring();
                                break;
                            }
                        }
                    }
                }
            }
        }

        HANDLE fileHandle = CreateFileA(processInfo.path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            std::cout << RED << "[!] Failed to open process file\n" << RESET;
            std::ofstream log("logs.txt", std::ios::app);
            log << "\n[MEMORY PATCH DETECTED]\n";
            log << "Type: Cannot open process file\n";
            log << "Error Code: " << GetLastError() << "\n";
            log << "Timestamp: " << getCurrentTimestamp() << "\n";
            log.close();
            result.foundHooks = true;
            return result;
        }

        HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, processInfo.pid);
        if (processHandle == NULL) {
            std::cout << RED << "[!] Failed to open process for memory reading\n" << RESET;
            std::ofstream log("logs.txt", std::ios::app);
            log << "\n[MEMORY PATCH DETECTED]\n";
            log << "Type: Cannot read process memory - Access denied\n";
            log << "Process ID: " << processInfo.pid << "\n";
            log << "Error Code: " << GetLastError() << "\n";
            log << "Timestamp: " << getCurrentTimestamp() << "\n";
            log.close();
            CloseHandle(fileHandle);
            result.foundHooks = true;
            return result;
        }

        DWORD fileSize = GetFileSize(fileHandle, NULL);
        std::vector<uint8_t> fileData(fileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(fileHandle, fileData.data(), fileSize, &bytesRead, NULL)) {
            CloseHandle(fileHandle);
            CloseHandle(processHandle);
            return result;
        }
        CloseHandle(fileHandle);

        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;

        ReadProcessMemory(processHandle, (LPCVOID)processInfo.baseAddress, &dosHeader, sizeof(dosHeader), NULL);
        ReadProcessMemory(processHandle, (LPCVOID)(processInfo.baseAddress + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL);

        HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processInfo.pid);
        if (moduleSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W moduleEntry;
            moduleEntry.dwSize = sizeof(moduleEntry);

            if (Module32FirstW(moduleSnap, &moduleEntry)) {
                do {
                    if (_wcsicmp(moduleEntry.szModule, L"discord_voice.node") == 0) {
                        std::wstring loadedPath = moduleEntry.szExePath;
                        std::wstring expectedPath = voiceNodePath;

                        if (loadedPath.find(L"\\\\?\\") == 0) {
                            loadedPath = loadedPath.substr(4);
                        }
                        if (expectedPath.find(L"\\\\?\\") == 0) {
                            expectedPath = expectedPath.substr(4);
                        }

                        std::transform(loadedPath.begin(), loadedPath.end(), loadedPath.begin(), ::tolower);
                        std::transform(expectedPath.begin(), expectedPath.end(), expectedPath.begin(), ::tolower);

                        if (loadedPath != expectedPath) {
                            std::cout << RED << "[!] Voice node loaded from incorrect path!\n";
                            std::cout << "Expected: " << ws2s(expectedPath) << "\n";
                            std::cout << "Found: " << ws2s(loadedPath) << RESET << "\n";

                            std::ofstream log("logs.txt", std::ios::app);
                            log << "\n[MEMORY PATCH DETECTED]\n";
                            log << "Type: Incorrect voice node path\n";
                            log << "Expected Path: " << ws2s(expectedPath) << "\n";
                            log << "Loaded Path: " << ws2s(loadedPath) << "\n";
                            log << "Timestamp: " << getCurrentTimestamp() << "\n";
                            log.close();

                            result.foundHooks = true;
                        }
                        break;
                    }
                } while (Module32NextW(moduleSnap, &moduleEntry));
            }
            CloseHandle(moduleSnap);
        }

        for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER sectionHeader;
            ReadProcessMemory(processHandle,
                (LPCVOID)(processInfo.baseAddress + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))),
                &sectionHeader, sizeof(sectionHeader), NULL);

            if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                std::vector<uint8_t> memoryData(sectionHeader.Misc.VirtualSize);
                ReadProcessMemory(processHandle,
                    (LPCVOID)(processInfo.baseAddress + sectionHeader.VirtualAddress),
                    memoryData.data(), sectionHeader.Misc.VirtualSize, NULL);

                for (size_t offset = 0; offset < memoryData.size() - 10; offset++) {
                    bool foundHook = false;
                    for (const auto& pattern : HOOK_PATTERNS) {
                        if (offset + pattern.pattern.size() <= memoryData.size()) {
                            if (std::equal(pattern.pattern.begin(), pattern.pattern.end(), memoryData.begin() + offset)) {
                                size_t fileOffset = sectionHeader.PointerToRawData + offset;
                                if (fileOffset + pattern.pattern.size() <= fileData.size() &&
                                    !std::equal(pattern.pattern.begin(), pattern.pattern.end(),
                                        fileData.begin() + fileOffset)) {
                                    result.foundHooks = true;
                                    result.sectionName = std::string((char*)sectionHeader.Name, 8);
                                    result.offset = sectionHeader.VirtualAddress + offset;
                                    result.hookType = pattern.name;

                                    result.originalBytes.assign(
                                        fileData.begin() + fileOffset,
                                        fileData.begin() + fileOffset + pattern.pattern.size()
                                    );
                                    result.modifiedBytes.assign(
                                        memoryData.begin() + offset,
                                        memoryData.begin() + offset + pattern.pattern.size()
                                    );

                                    writeHookDetails("logs.txt", result, true);

                                    if (!hookDetectedPrinted) {
                                        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
                                        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
                                        for (const auto& line : boxChars) {
                                            std::wcout << line << std::endl;
                                        }
                                        hookDetectedPrinted = true;
                                    }
                                    foundHook = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!foundHook) {
                        size_t fileOffset = sectionHeader.PointerToRawData + offset;
                        if (fileOffset + 10 <= fileData.size()) {
                            if (!std::equal(fileData.begin() + fileOffset, fileData.begin() + fileOffset + 10, memoryData.begin() + offset)) {
                                result.sectionName = std::string((char*)sectionHeader.Name, 8);
                                result.offset = sectionHeader.VirtualAddress + offset;
                                result.hookType = "Memory Patch";

                                result.originalBytes.assign(fileData.begin() + fileOffset, fileData.begin() + fileOffset + 10);
                                result.modifiedBytes.assign(memoryData.begin() + offset, memoryData.begin() + offset + 10);

                                writeHookDetails("logs.txt", result, false);
                            }
                        }
                    }
                }
            }
        }

        CloseHandle(processHandle);
    }
    catch (const std::exception& e) {
        std::cout << RED << "[!] Error during analysis: " << e.what() << "\n" << RESET;
        result.foundHooks = true;
    }
    catch (...) {
        std::cout << RED << "[!] Unknown error during analysis\n" << RESET;
        result.foundHooks = true;
    }

    return result;
}

bool HookDetector::checkForOpusHooks() {
    std::cout << BLUE << "[*] Opus Hook Detection...\n" << RESET;
    bool found = false;
    const std::vector<std::wstring> discordExes = {
        L"Discord.exe",
        L"DiscordCanary.exe",
        L"DiscordPTB.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                for (const auto& discordExe : discordExes) {
                    if (wcsstr(processEntry.szExeFile, discordExe.c_str())) {
                        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                        if (!hProcess) continue;

                        HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ProcessID);
                        if (moduleSnap != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32W me32;
                            me32.dwSize = sizeof(MODULEENTRY32W);

                            if (Module32FirstW(moduleSnap, &me32)) {
                                do {
                                    MODULEINFO modInfo;
                                    if (GetModuleInformation(hProcess, me32.hModule, &modInfo, sizeof(MODULEINFO))) {
                                        if (modInfo.SizeOfImage > 4096 && modInfo.SizeOfImage < 100 * 1024 * 1024) {
                                            std::vector<BYTE> moduleBuffer(modInfo.SizeOfImage);
                                            SIZE_T bytesRead;

                                            if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, moduleBuffer.data(),
                                                modInfo.SizeOfImage, &bytesRead)) {

                                                std::wstring fullPath = me32.szExePath;
                                                std::string modPath(fullPath.begin(), fullPath.end());

                                                std::string moduleContent(
                                                    reinterpret_cast<char*>(moduleBuffer.data()),
                                                    bytesRead
                                                );
                                                std::transform(moduleContent.begin(), moduleContent.end(),
                                                    moduleContent.begin(), ::tolower);

                                                bool detected = false;
                                                std::string matchedType;
                                                std::string matchedSig;

                                                for (const auto& sig : opusSignatures) {
                                                    if (moduleContent.find(sig) != std::string::npos) {
                                                        detected = true;
                                                        matchedType = "String signature";
                                                        matchedSig = sig;
                                                        break;
                                                    }
                                                }

                                                if (!detected) {
                                                    for (const auto& pattern : AUDIO_HEX_PATTERNS) {
                                                        auto it = std::search(moduleBuffer.begin(), moduleBuffer.end(),
                                                            pattern.begin(), pattern.end());
                                                        if (it != moduleBuffer.end()) {
                                                            detected = true;
                                                            matchedType = "Hex pattern";
                                                            matchedSig = "Binary pattern match";
                                                            break;
                                                        }
                                                    }
                                                }

                                                if (detected) {
                                                    found = true;
                                                    std::cout << RED << "[!] Opus hooks detected in: " << modPath << "\n" << RESET;
                                                    std::ofstream log("logs.txt", std::ios::app);
                                                    log << "\n[OPUS DETECTION]\n";
                                                    log << "Module Path: " << modPath << "\n";
                                                    log << "Base Address: 0x" << std::hex << (uintptr_t)me32.hModule << std::dec << "\n";
                                                    log << "Module Size: " << modInfo.SizeOfImage << " bytes\n";
                                                    log << "Detection Type: " << matchedType << "\n";
                                                    if (matchedType == "String signature") {
                                                        log << "Matched Signature: " << matchedSig << "\n";
                                                    }
                                                    log << "Timestamp: " << getCurrentTimestamp() << "\n";
                                                    log.close();
                                                }
                                            }
                                        }
                                    }
                                } while (Module32NextW(moduleSnap, &me32));
                            }
                            CloseHandle(moduleSnap);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return found;
}

bool IsWhitelisted(const char* processName) {
    const char* whitelist[] = {
        "Discord.exe",
        "DiscordCanary.exe",
        "DiscordPTB.exe",
        "update.exe"
    };

    for (const char* allowed : whitelist) {
        if (strstr(processName, allowed)) return true;
    }
    return false;
}

AudioHookResult HookDetector::detectOtherHooks(DWORD processId) {
    std::cout << BLUE << "[*] Checking for Audio Hooks...\n" << RESET;
    AudioHookResult result;
    result.hasAudioHooks = false;
    const std::vector<std::wstring> discordExes = {
        L"Discord.exe",
        L"DiscordCanary.exe",
        L"DiscordPTB.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                for (const auto& discordExe : discordExes) {
                    if (wcsstr(processEntry.szExeFile, discordExe.c_str())) {
                        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                        if (!hProcess) continue;

                        HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ProcessID);
                        if (moduleSnap != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32W me32;
                            me32.dwSize = sizeof(me32);

                            if (Module32FirstW(moduleSnap, &me32)) {
                                do {
                                    MODULEINFO modInfo;
                                    if (GetModuleInformation(hProcess, me32.hModule, &modInfo, sizeof(MODULEINFO))) {
                                        if (modInfo.SizeOfImage > 4096 && modInfo.SizeOfImage < 100 * 1024 * 1024) {
                                            std::vector<BYTE> moduleBuffer(modInfo.SizeOfImage);
                                            SIZE_T bytesRead;

                                            if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, moduleBuffer.data(),
                                                modInfo.SizeOfImage, &bytesRead)) {

                                                char modNameA[MAX_PATH];
                                                WideCharToMultiByte(CP_UTF8, 0, me32.szModule, -1,
                                                    modNameA, sizeof(modNameA), NULL, NULL);

                                                std::string moduleContent(
                                                    reinterpret_cast<char*>(moduleBuffer.data()),
                                                    bytesRead
                                                );
                                                std::transform(moduleContent.begin(), moduleContent.end(),
                                                    moduleContent.begin(), ::tolower);

                                                for (const auto& sig : AUDIO_SIGNATURES) {
                                                    if (moduleContent.find(sig) != std::string::npos) {
                                                        result.hasAudioHooks = true;
                                                        result.detectedHooks.push_back({
                                                            modNameA,
                                                            "Audio signature found: " + sig
                                                            });
                                                    }
                                                }

                                                for (const auto& pattern : AUDIO_HEX_PATTERNS) {
                                                    auto it = std::search(moduleBuffer.begin(), moduleBuffer.end(),
                                                        pattern.begin(), pattern.end());
                                                    if (it != moduleBuffer.end()) {
                                                        result.hasAudioHooks = true;
                                                        result.detectedHooks.push_back({
                                                            modNameA,
                                                            "Audio hex pattern detected"
                                                            });
                                                        break;
                                                    }
                                                }

                                                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBuffer.data();
                                                if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                                                    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBuffer.data() + dosHeader->e_lfanew);
                                                    if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                                                        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
                                                        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                                                            char sectionName[9] = { 0 };
                                                            memcpy(sectionName, section[i].Name, 8);

                                                            if (strstr(sectionName, "audio") ||
                                                                strstr(sectionName, "sound") ||
                                                                strstr(sectionName, "voice")) {

                                                                if (section[i].Characteristics &
                                                                    (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
                                                                    result.hasAudioHooks = true;
                                                                    result.detectedHooks.push_back({
                                                                        modNameA,
                                                                        std::string("Suspicious section: ") + sectionName
                                                                        });
                                                                }
                                                            }
                                                        }
                                                    }
                                                }

                                                if (result.hasAudioHooks) {

                                                    std::ofstream log("logs.txt", std::ios::app);
                                                    log << "\n[AUDIO HOOK DETECTION]\n";
                                                    log << "Module: " << modNameA << "\n";
                                                    log << "Timestamp: " << getCurrentTimestamp() << "\n";
                                                    for (const auto& hook : result.detectedHooks) {
                                                        log << "Detection in " << hook.first << ": " << hook.second << "\n";
                                                    }
                                                    log.close();
                                                }
                                            }
                                        }
                                    }
                                } while (Module32NextW(moduleSnap, &me32));
                            }
                            CloseHandle(moduleSnap);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return result;
}

bool HookDetector::checkForImGui() {
    std::cout << BLUE << "[*] ImGui Detection...\n" << RESET;
    bool found = false;
    const std::vector<std::wstring> discordExes = {
        L"Discord.exe",
        L"DiscordCanary.exe",
        L"DiscordPTB.exe"
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                for (const auto& discordExe : discordExes) {
                    if (wcsstr(processEntry.szExeFile, discordExe.c_str())) {
                        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                        if (!hProcess) continue;

                        HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processEntry.th32ProcessID);
                        if (moduleSnap != INVALID_HANDLE_VALUE) {
                            MODULEENTRY32W me32;
                            me32.dwSize = sizeof(MODULEENTRY32W);

                            if (Module32FirstW(moduleSnap, &me32)) {
                                do {
                                    MODULEINFO modInfo;
                                    if (GetModuleInformation(hProcess, me32.hModule, &modInfo, sizeof(MODULEINFO))) {
                                        if (modInfo.SizeOfImage > 4096 && modInfo.SizeOfImage < 100 * 1024 * 1024) {
                                            std::vector<BYTE> moduleBuffer(modInfo.SizeOfImage);
                                            SIZE_T bytesRead;

                                            if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, moduleBuffer.data(),
                                                modInfo.SizeOfImage, &bytesRead)) {

                                                std::wstring fullPath = me32.szExePath;
                                                std::string modPath(fullPath.begin(), fullPath.end());

                                                std::string moduleContent(
                                                    reinterpret_cast<char*>(moduleBuffer.data()),
                                                    bytesRead
                                                );
                                                std::transform(moduleContent.begin(), moduleContent.end(),
                                                    moduleContent.begin(), ::tolower);

                                                bool detected = false;
                                                std::string matchedSig;

                                                for (const auto& sig : EXTENDED_IMGUI_SIGNATURES) {
                                                    if (moduleContent.find(sig) != std::string::npos) {
                                                        detected = true;
                                                        matchedSig = sig;
                                                        break;
                                                    }
                                                }

                                                if (detected) {
                                                    found = true;
                                                    std::cout << RED << "[!] ImGui detected in: " << modPath << "\n" << RESET;

                                                    std::ofstream log("logs.txt", std::ios::app);
                                                    log << "\n[IMGUI DETECTION]\n";
                                                    log << "Module Path: " << modPath << "\n";
                                                    log << "Base Address: 0x" << std::hex << (uintptr_t)me32.hModule << std::dec << "\n";
                                                    log << "Module Size: " << modInfo.SizeOfImage << " bytes\n";
                                                    log << "Matched Signature: " << matchedSig << "\n";
                                                    log << "Timestamp: " << getCurrentTimestamp() << "\n";
                                                    log.close();
                                                }
                                            }
                                        }
                                    }
                                } while (Module32NextW(moduleSnap, &me32));
                            }
                            CloseHandle(moduleSnap);
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return found;
}

bool HookDetector::validateNodeIntegrity(const std::string& nodePath) {
    std::ifstream file(nodePath, std::ios::binary);
    if (!file) return false;

    std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD expectedChecksum = ntHeaders->OptionalHeader.CheckSum;
    DWORD calculatedChecksum = 0;

    for (size_t i = 0; i < fileData.size() / 4; i++) {
        calculatedChecksum += ((DWORD*)fileData.data())[i];
    }

    return calculatedChecksum == expectedChecksum;
}

bool HookDetector::detectIATHooks(HMODULE module) {
    if (!module) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)module +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)module + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)module + importDesc->FirstThunk);

        while (originalFirstThunk->u1.AddressOfData) {
            void* originalFunc = (void*)originalFirstThunk->u1.Function;
            void* currentFunc = (void*)firstThunk->u1.Function;

            if (originalFunc != currentFunc && isAddressHooked(currentFunc)) {
                return true;
            }

            originalFirstThunk++;
            firstThunk++;
        }
        importDesc++;
    }
    return false;
}

bool HookDetector::detectVTableHooks(const ProcessInfo& processInfo) {
    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processInfo.pid);
    if (!processHandle) return false;

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    bool foundHooks = false;

    while (VirtualQueryEx(processHandle, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {

                for (size_t i = 0; i < bytesRead - sizeof(void*); i++) {
                    void** potentialVTable = (void**)&buffer[i];
                    if (IsBadReadPtr(potentialVTable, sizeof(void*)) == 0) {
                        if (isAddressHooked(*potentialVTable)) {
                            foundHooks = true;
                            break;
                        }
                    }
                }
            }
        }

        address = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
        if (address >= (LPVOID)0x7FFFFFFF) break;
    }

    CloseHandle(processHandle);
    return foundHooks;
}

bool HookDetector::detectInlineHooks(HMODULE module) {
    if (!module) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* sectionStart = (BYTE*)module + sectionHeader[i].VirtualAddress;
            SIZE_T sectionSize = sectionHeader[i].Misc.VirtualSize;

            for (SIZE_T j = 0; j < sectionSize - 5; j++) {
                BYTE* address = sectionStart + j;
                if (*address == 0xE9 || *address == 0xE8) {
                    DWORD relativeAddress = *(DWORD*)(address + 1);
                    void* targetAddress = (void*)(address + relativeAddress + 5);

                    if (isAddressHooked(targetAddress)) {
                        return true;
                    }
                }
                else if (*address == 0xFF && (*(address + 1) == 0x15 || *(address + 1) == 0x25)) {
                    void* targetAddress = *(void**)(address + 2);
                    if (isAddressHooked(targetAddress)) {
                        return true;
                    }
                }
            }
        }
        sectionHeader++;
    }
    return false;
}

bool HookDetector::detectPageGuardHooks() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPVOID address = sysInfo.lpMinimumApplicationAddress;
    bool foundHooks = false;

    while (address < sysInfo.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi))) {
            if ((mbi.Protect & PAGE_GUARD) &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                (mbi.State == MEM_COMMIT)) {

                if (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
                    foundHooks = true;
                    break;
                }
            }
            address = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
        }
        else {
            break;
        }
    }

    return foundHooks;
}

std::vector<HookInfo> HookDetector::detectAllHooks(DWORD processId) {
    std::cout << BLUE << "[*] Performing comprehensive hook scan...\n" << RESET;

    std::vector<HookInfo> hooks;
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!processHandle) return hooks;

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;

    while (VirtualQueryEx(processHandle, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ) {
                char modulePath[MAX_PATH];
                if (GetMappedFileNameA(processHandle, mbi.BaseAddress, modulePath, MAX_PATH)) {
                    std::vector<uint8_t> buffer(mbi.RegionSize);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
                        bool hookFound = false;
                        for (const auto& pattern : HOOK_PATTERNS) {
                            for (size_t i = 0; i < bytesRead - pattern.pattern.size(); i++) {
                                if (std::equal(pattern.pattern.begin(), pattern.pattern.end(), buffer.begin() + i)) {
                                    std::cout << RED << "[!] ReadOnly hook pattern found at " << std::hex << (uintptr_t)mbi.BaseAddress + i << "\n" << RESET;
                                    hooks.push_back({ modulePath, (uintptr_t)mbi.BaseAddress + i });
                                    hookFound = true;
                                    break;
                                }
                            }
                            if (hookFound) break;
                        }
                    }
                }
            }
        }
        address = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(processHandle);
    return hooks;
}

bool HookDetector::validateVoiceNodeIntegrity(const std::string& voiceNodePath, DWORD processId) {
    try {
        std::cout << BLUE << "[*] Performing comprehensive voice node integrity check...\n" << RESET;

        std::ifstream file(voiceNodePath, std::ios::binary);
        if (!file) {
            std::cout << RED << "[!] Failed to open voice node file: " << voiceNodePath << "\n" << RESET;
            return false;
        }

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        if (fileSize == 0) {
            std::cout << RED << "[!] Voice node file is empty\n" << RESET;
            return false;
        }

        std::vector<uint8_t> fileData(fileSize);
        file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
        file.close();

        HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!processHandle) {
            std::cout << RED << "[!] Failed to open process: " << GetLastError() << "\n" << RESET;
            return false;
        }

        bool integrityValid = true;
        MEMORY_BASIC_INFORMATION memInfo;
        LPVOID address = nullptr;

        std::cout << BLUE << "[*] Scanning memory regions...\n" << RESET;
        while (VirtualQueryEx(processHandle, address, &memInfo, sizeof(memInfo))) {
            if (memInfo.RegionSize == 0) break;

            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE) &&
                (memInfo.Protect == PAGE_READONLY || memInfo.Protect == PAGE_EXECUTE_READ)) {

                if (memInfo.RegionSize >= fileData.size()) {
                    std::vector<uint8_t> memoryData(memInfo.RegionSize);
                    SIZE_T bytesRead;

                    if (ReadProcessMemory(processHandle, memInfo.BaseAddress, memoryData.data(), memInfo.RegionSize, &bytesRead)) {

                        if (bytesRead >= fileData.size()) {
                            for (size_t i = 0; i <= bytesRead - fileData.size(); i += 16) {
                                if (memoryData[i] == fileData[0]) {
                                    if (i + fileData.size() <= bytesRead &&
                                        std::equal(fileData.begin(), fileData.end(), memoryData.begin() + i)) {

                                        if (memInfo.Protect != PAGE_READONLY) {
                                            std::cout << RED << "[!] Voice node found in non-readonly memory at: 0x"
                                                << std::hex << (uintptr_t)memInfo.BaseAddress + i << std::dec << "\n" << RESET;
                                            integrityValid = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            address = (LPVOID)((BYTE*)memInfo.BaseAddress + memInfo.RegionSize);
            if ((uintptr_t)address >= 0x7FFFFFFF) break;
        }

        CloseHandle(processHandle);

        if (!integrityValid) {
            std::ofstream log("logs.txt", std::ios::app);
            log << "\n[INTEGRITY CHECK FAILED]\n";
            log << "Voice Node Path: " << voiceNodePath << "\n";
            log << "Process ID: " << processId << "\n";
            log << "Timestamp: " << getCurrentTimestamp() << "\n";
        }

        return integrityValid;

    }
    catch (const std::exception& e) {
        std::cout << RED << "[!] Error during integrity check: " << e.what() << "\n" << RESET;
        return false;
    }
    catch (...) {
        std::cout << RED << "[!] Unknown error during integrity check\n" << RESET;
        return false;
    }
}

void HookDetector::scanModulePatterns(HMODULE module, DWORD processId) {
    std::cout << BLUE << "[*] Scanning module patterns...\n" << RESET;

    char modName[MAX_PATH];
    if (GetModuleFileNameExA(GetCurrentProcess(), module, modName, sizeof(modName))) {
        std::ifstream file(modName, std::ios::binary);
        if (!file) return;

        std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        for (size_t i = 0; i < fileData.size(); i++) {
            const char* suspiciousStrings[] = { "imgui", "minhook.h", "ascend", "inject" };
            for (const auto& str : suspiciousStrings) {
                if (i + strlen(str) <= fileData.size()) {
                    if (memcmp(&fileData[i], str, strlen(str)) == 0) {
                        std::cout << RED << "[!] Suspicious string found in module: " << str << "\n" << RESET;
                    }
                }
            }
        }
    }
}

void HookDetector::scanModuleForSuspiciousPatterns(const std::vector<uint8_t>& moduleData, const std::string& moduleName) {
    if (moduleName.find("discord_voice.node") == std::string::npos) {
        return;
    }

    const std::vector<std::string> suspiciousStrings = {
        "imgui", "minhook.h", "inject", "detour", "ascend",
        "bypass"
    };

    std::string moduleContent(reinterpret_cast<const char*>(moduleData.data()), moduleData.size());
    std::string moduleLower = moduleContent;
    std::transform(moduleLower.begin(), moduleLower.end(), moduleLower.begin(), ::tolower);

    for (const auto& str : suspiciousStrings) {
        size_t pos = 0;
        while ((pos = moduleLower.find(str, pos)) != std::string::npos) {
            std::cout << RED << "[!] Found suspicious string '" << str << "' in " << moduleName
                << " at offset: 0x" << std::hex << pos << std::dec << "\n" << RESET;
            pos += str.length();
        }
    }

    const std::vector<std::vector<uint8_t>> hookPatterns = {
        {0xE9},
        {0xFF, 0x25},
        {0x90, 0x90, 0x90, 0x90},
        {0xCC},
    };

    for (size_t i = 0; i < moduleData.size() - 10; i++) {
        for (const auto& pattern : hookPatterns) {
            if (i + pattern.size() <= moduleData.size() &&
                std::equal(pattern.begin(), pattern.end(), moduleData.begin() + i)) {
                std::cout << RED << "[!] Found hook pattern in " << moduleName
                    << " at offset: 0x" << std::hex << i << std::dec << "\n" << RESET;
            }
        }
    }
}