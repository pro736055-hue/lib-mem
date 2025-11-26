#include "Memory.hpp"
#include "Proc.hpp"
#include "Imps.hpp"
#include "MemoryRegionResult.hpp"
#include <psapi.h>
#include <TlHelp32.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace MemoryLib {

    Mem::Mem() {
    }

    Mem::~Mem() {
        CloseProcess();
    }

    bool Mem::OpenProcess(const char* procName) {
        DWORD pid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        DWORD threadCount = 0;
        if (Process32First(hSnap, &pe)) {
            do {
#ifdef UNICODE
                char procNameA[260];
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procNameA, 260, NULL, NULL);
                if (_stricmp(procNameA, procName) == 0) {
#else
                if (_stricmp(pe.szExeFile, procName) == 0) {
#endif
                    if (pe.cntThreads > threadCount) {
                        threadCount = pe.cntThreads;
                        pid = pe.th32ProcessID;
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);

        if (pid == 0) {
            return false;
        }

        return OpenProcess(pid);
    }

    int Mem::GetProcIdFromName(const std::string& name) {
        std::string procName = name;
        
        std::transform(procName.begin(), procName.end(), procName.begin(), ::tolower);
        if (procName.find(".exe") != std::string::npos) {
            procName = procName.substr(0, procName.find(".exe"));
        }
        if (procName.find(".bin") != std::string::npos) {
            procName = procName.substr(0, procName.find(".bin"));
        }
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnap, &pe)) {
            do {
#ifdef UNICODE
                char procNameA[260];
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procNameA, 260, NULL, NULL);
                std::string currentName = procNameA;
#else
                std::string currentName = pe.szExeFile;
#endif
                std::transform(currentName.begin(), currentName.end(), currentName.begin(), ::tolower);
                
                if (currentName.find(".exe") != std::string::npos) {
                    currentName = currentName.substr(0, currentName.find(".exe"));
                }
                
                if (currentName == procName) {
                    CloseHandle(hSnap);
                    return pe.th32ProcessID;
                }
            } while (Process32Next(hSnap, &pe));
        }
        
        CloseHandle(hSnap);
        return 0;
    }

    bool Mem::OpenProcess(DWORD processId) {
        if (processId == 0) {
            return false;
        }

        CloseProcess();

        m_proc.Handle = ::OpenProcess(PROCESS_ALL_ACCESS, TRUE, processId);

        if (m_proc.Handle == nullptr) {
            return false;
        }

        BOOL isWow64 = FALSE;
        IsWow64Process(m_proc.Handle, &isWow64);
        m_proc.Is64Bit = (sizeof(void*) == 8) && !isWow64;

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(m_proc.Handle, hMods, sizeof(hMods), &cbNeeded)) {
            if (cbNeeded > 0) {
                GetModuleInformation(m_proc.Handle, hMods[0], &m_proc.MainModule, sizeof(MODULEINFO));
            }
        }

        return true;
    }

    void Mem::CloseProcess() {
        if (m_proc.Handle != nullptr) {
            CloseHandle(m_proc.Handle);
            m_proc.Handle = nullptr;
        }
        ZeroMemory(&m_proc.MainModule, sizeof(MODULEINFO));
        m_proc.Is64Bit = false;
    }

    Mem::PatternData Mem::ParsePattern(const std::string& patternStr) {
        PatternData result;
        std::istringstream iss(patternStr);
        std::string byteStr;

        while (iss >> byteStr) {
            if (byteStr == "??" || byteStr == "?") {
                result.pattern.push_back(0x00);
                result.mask.push_back(0x00);
            } else if (byteStr.length() == 2) {
                if (byteStr[0] == '?' && isxdigit(byteStr[1])) {
                    std::string tempStr = std::string("0") + byteStr[1];
                    BYTE byteValue = (BYTE)strtoul(tempStr.c_str(), nullptr, 16);
                    result.pattern.push_back(byteValue);
                    result.mask.push_back(0x0F);
                } else if (byteStr[1] == '?' && isxdigit(byteStr[0])) {
                    std::string tempStr = std::string(1, byteStr[0]) + "0";
                    BYTE byteValue = (BYTE)strtoul(tempStr.c_str(), nullptr, 16);
                    result.pattern.push_back(byteValue);
                    result.mask.push_back(0xF0);
                } else {
                    BYTE byteValue = (BYTE)strtoul(byteStr.c_str(), nullptr, 16);
                    result.pattern.push_back(byteValue);
                    result.mask.push_back(0xFF);
                }
            } else {
                BYTE byteValue = (BYTE)strtoul(byteStr.c_str(), nullptr, 16);
                result.pattern.push_back(byteValue);
                result.mask.push_back(0xFF);
            }
        }

        return result;
    }

    int Mem::FindPatternInBuffer(const BYTE* buffer, size_t bufferSize, const PatternData& patternData, int startOffset) {
        if (bufferSize == 0 || patternData.pattern.empty() || startOffset > (int)bufferSize - (int)patternData.pattern.size()) {
            return -1;
        }

        for (int i = startOffset; i <= (int)bufferSize - (int)patternData.pattern.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < patternData.pattern.size(); j++) {
                if ((buffer[i + j] & patternData.mask[j]) != (patternData.pattern[j] & patternData.mask[j])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }

        return -1;
    }

    bool Mem::IsValidMemoryRegion(DWORD_PTR address, size_t size, bool writable, bool executable) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(m_proc.Handle, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        if (mbi.Protect & PAGE_GUARD || mbi.Protect == PAGE_NOACCESS) {
            return false;
        }

        if (writable && !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY))) {
            return false;
        }

        if (executable && !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            return false;
        }

        return true;
    }

    std::vector<DWORD_PTR> Mem::AoBScan(const std::string& pattern, bool writable, bool executable) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        return AoBScan((DWORD_PTR)si.lpMinimumApplicationAddress, (DWORD_PTR)si.lpMaximumApplicationAddress, pattern, writable, executable);
    }

    std::vector<DWORD_PTR> Mem::AoBScan(DWORD_PTR start, DWORD_PTR end, const std::string& pattern, bool writable, bool executable) {
        std::vector<DWORD_PTR> results;

        if (m_proc.Handle == nullptr) {
            return results;
        }

        PatternData patternData = ParsePattern(pattern);
        if (patternData.pattern.empty()) {
            return results;
        }

        SYSTEM_INFO si;
        GetSystemInfo(&si);

        DWORD_PTR currentAddress = (start < (DWORD_PTR)si.lpMinimumApplicationAddress) ? 
            (DWORD_PTR)si.lpMinimumApplicationAddress : start;
        DWORD_PTR maxAddress = (end > (DWORD_PTR)si.lpMaximumApplicationAddress) ? 
            (DWORD_PTR)si.lpMaximumApplicationAddress : end;

        struct MemoryRegion {
            DWORD_PTR baseAddress;
            SIZE_T regionSize;
        };
        std::vector<MemoryRegion> validRegions;

        MEMORY_BASIC_INFORMATION mbi;
        while (currentAddress < maxAddress) {
            if (VirtualQueryEx(m_proc.Handle, (LPCVOID)currentAddress, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            bool isValid = (mbi.State == MEM_COMMIT);
            isValid &= ((DWORD_PTR)mbi.BaseAddress < (DWORD_PTR)si.lpMaximumApplicationAddress);
            isValid &= !(mbi.Protect & PAGE_GUARD);
            isValid &= (mbi.Protect != PAGE_NOACCESS);
            isValid &= (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE);

            if (isValid) {
                bool isReadable = (mbi.Protect & PAGE_READONLY) != 0;
                bool isWritable = (mbi.Protect & PAGE_READWRITE) != 0 || 
                                  (mbi.Protect & PAGE_WRITECOPY) != 0 || 
                                  (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 || 
                                  (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                bool isExecutable = (mbi.Protect & PAGE_EXECUTE) != 0 || 
                                    (mbi.Protect & PAGE_EXECUTE_READ) != 0 || 
                                    (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 || 
                                    (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

                if (writable && !isWritable) {
                    isValid = false;
                }
                if (executable && !isExecutable) {
                    isValid = false;
                }
            }

            if (isValid) {
                if (!validRegions.empty()) {
                    MemoryRegion& lastRegion = validRegions.back();
                    if ((DWORD_PTR)lastRegion.baseAddress + lastRegion.regionSize == (DWORD_PTR)mbi.BaseAddress) {
                        lastRegion.regionSize += mbi.RegionSize;
                    } else {
                        validRegions.push_back({(DWORD_PTR)mbi.BaseAddress, mbi.RegionSize});
                    }
                } else {
                    validRegions.push_back({(DWORD_PTR)mbi.BaseAddress, mbi.RegionSize});
                }
            }

            currentAddress = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize;
        }

        for (const auto& region : validRegions) {
            std::vector<BYTE> buffer(region.regionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(m_proc.Handle, (LPCVOID)region.baseAddress, buffer.data(), region.regionSize, &bytesRead)) {
                int offset = 0;
                while ((offset = FindPatternInBuffer(buffer.data(), bytesRead, patternData, offset)) != -1) {
                    DWORD_PTR foundAddress = region.baseAddress + offset;
                    results.push_back(foundAddress);
                    offset += patternData.pattern.size();
                }
            }
        }

        std::sort(results.begin(), results.end());

        return results;
    }

    template<typename T>
    T Mem::ReadMemory(DWORD_PTR address) {
        T value = T();
        SIZE_T bytesRead = 0;
        ReadProcessMemory(m_proc.Handle, (LPCVOID)address, &value, sizeof(T), &bytesRead);
        return value;
    }

    template<typename T>
    T Mem::ReadMemory(const std::string& addressHex) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return T();
        }
        return ReadMemory<T>(address);
    }

    int Mem::ReadInt(DWORD_PTR address) {
        return ReadMemory<int>(address);
    }

    int Mem::ReadInt(const std::string& addressHex) {
        return ReadMemory<int>(addressHex);
    }

    float Mem::ReadFloat(DWORD_PTR address) {
        return ReadMemory<float>(address);
    }

    float Mem::ReadFloat(const std::string& addressHex) {
        return ReadMemory<float>(addressHex);
    }

    long Mem::ReadLong(DWORD_PTR address) {
        return ReadMemory<long>(address);
    }

    long Mem::ReadLong(const std::string& addressHex) {
        return ReadMemory<long>(addressHex);
    }

    std::vector<BYTE> Mem::ReadBytes(DWORD_PTR address, size_t length) {
        std::vector<BYTE> buffer(length);
        SIZE_T bytesRead = 0;
        ReadProcessMemory(m_proc.Handle, (LPCVOID)address, buffer.data(), length, &bytesRead);
        buffer.resize(bytesRead);
        return buffer;
    }

    std::vector<BYTE> Mem::ReadBytes(const std::string& addressHex, size_t length) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return std::vector<BYTE>();
        }
        return ReadBytes(address, length);
    }

    bool Mem::WriteMemory(const std::string& addressHex, const std::vector<BYTE>& bytes) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return false;
        }
        return WriteMemory(address, bytes);
    }

    bool Mem::WriteMemory(DWORD_PTR address, const std::vector<BYTE>& bytes) {
        if (m_proc.Handle == nullptr) {
            return false;
        }

        DWORD oldProtect = 0;
        VirtualProtectEx(m_proc.Handle, (LPVOID)address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
        
        SIZE_T bytesWritten = 0;
        bool result = WriteProcessMemory(m_proc.Handle, (LPVOID)address, bytes.data(), bytes.size(), &bytesWritten);
        
        VirtualProtectEx(m_proc.Handle, (LPVOID)address, bytes.size(), oldProtect, &oldProtect);
        
        return result && (bytesWritten == bytes.size());
    }

    bool Mem::WriteMemory(DWORD_PTR address, int value) {
        BYTE* bytes = (BYTE*)&value;
        return WriteMemory(address, std::vector<BYTE>(bytes, bytes + sizeof(int)));
    }

    bool Mem::WriteMemory(const std::string& addressHex, int value) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return false;
        }
        return WriteMemory(address, value);
    }

    bool Mem::WriteMemory(DWORD_PTR address, float value) {
        BYTE* bytes = (BYTE*)&value;
        return WriteMemory(address, std::vector<BYTE>(bytes, bytes + sizeof(float)));
    }

    bool Mem::WriteMemory(const std::string& addressHex, float value) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return false;
        }
        return WriteMemory(address, value);
    }

    bool Mem::WriteMemory(DWORD_PTR address, long value) {
        BYTE* bytes = (BYTE*)&value;
        return WriteMemory(address, std::vector<BYTE>(bytes, bytes + sizeof(long)));
    }

    bool Mem::WriteMemory(const std::string& addressHex, long value) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return false;
        }
        return WriteMemory(address, value);
    }

    bool Mem::WriteMemory(const std::string& addressHex, const std::string& type, const std::string& value) {
        DWORD_PTR address = HexStringToAddress(addressHex);
        if (address == 0 || address < 0x10000) {
            return false;
        }
        return WriteMemory(address, type, value);
    }

    bool Mem::WriteMemory(DWORD_PTR address, const std::string& type, const std::string& value) {
        if (m_proc.Handle == nullptr) {
            return false;
        }

        std::vector<BYTE> bytes;

        std::string typeLower = type;
        std::transform(typeLower.begin(), typeLower.end(), typeLower.begin(), ::tolower);

        if (typeLower == "bytes" || typeLower == "byte") {
            std::string cleanValue = value;
            std::replace(cleanValue.begin(), cleanValue.end(), ',', ' ');
            std::istringstream iss(cleanValue);
            std::string byteStr;
            while (iss >> byteStr) {
                BYTE byteValue = (BYTE)strtoul(byteStr.c_str(), nullptr, 16);
                bytes.push_back(byteValue);
            }
        } else if (typeLower == "int") {
            int intValue = atoi(value.c_str());
            bytes.assign((BYTE*)&intValue, (BYTE*)&intValue + sizeof(int));
        } else if (typeLower == "float") {
            float floatValue = (float)atof(value.c_str());
            bytes.assign((BYTE*)&floatValue, (BYTE*)&floatValue + sizeof(float));
        } else if (typeLower == "long") {
            long longValue = atol(value.c_str());
            bytes.assign((BYTE*)&longValue, (BYTE*)&longValue + sizeof(long));
        } else if (typeLower == "double") {
            double doubleValue = atof(value.c_str());
            bytes.assign((BYTE*)&doubleValue, (BYTE*)&doubleValue + sizeof(double));
        } else if (typeLower == "2bytes") {
            int intValue = atoi(value.c_str());
            bytes.push_back((BYTE)(intValue % 256));
            bytes.push_back((BYTE)(intValue / 256));
        } else if (typeLower == "string") {
            bytes.assign(value.begin(), value.end());
        }

        if (bytes.empty()) {
            return false;
        }

        return WriteMemory(address, bytes);
    }

    DWORD_PTR Mem::HexStringToAddress(const std::string& hexStr) {
        return (DWORD_PTR)strtoull(hexStr.c_str(), nullptr, 16);
    }

    template int Mem::ReadMemory<int>(DWORD_PTR);
    template float Mem::ReadMemory<float>(DWORD_PTR);
    template long Mem::ReadMemory<long>(DWORD_PTR);
    template int Mem::ReadMemory<int>(const std::string&);
    template float Mem::ReadMemory<float>(const std::string&);
    template long Mem::ReadMemory<long>(const std::string&);
}

