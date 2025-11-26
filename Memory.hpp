#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include "Proc.hpp"
#include "Imps.hpp"
#include "MemoryRegionResult.hpp"

namespace MemoryLib {
    class Mem {
    public:
        Mem();
        ~Mem();

        bool OpenProcess(const char* procName);
        bool OpenProcess(DWORD processId);
        void CloseProcess();
        
        int GetProcIdFromName(const std::string& name);

        std::vector<DWORD_PTR> AoBScan(const std::string& pattern, bool writable = false, bool executable = true);
        std::vector<DWORD_PTR> AoBScan(DWORD_PTR start, DWORD_PTR end, const std::string& pattern, bool writable = false, bool executable = true);

        template<typename T>
        T ReadMemory(DWORD_PTR address);
        
        template<typename T>
        T ReadMemory(const std::string& addressHex);

        int ReadInt(DWORD_PTR address);
        int ReadInt(const std::string& addressHex);
        float ReadFloat(DWORD_PTR address);
        float ReadFloat(const std::string& addressHex);
        long ReadLong(DWORD_PTR address);
        long ReadLong(const std::string& addressHex);
        std::vector<BYTE> ReadBytes(DWORD_PTR address, size_t length);
        std::vector<BYTE> ReadBytes(const std::string& addressHex, size_t length);

        bool WriteMemory(DWORD_PTR address, const std::string& type, const std::string& value);
        bool WriteMemory(const std::string& addressHex, const std::string& type, const std::string& value);
        bool WriteMemory(DWORD_PTR address, const std::vector<BYTE>& bytes);
        bool WriteMemory(const std::string& addressHex, const std::vector<BYTE>& bytes);
        bool WriteMemory(DWORD_PTR address, int value);
        bool WriteMemory(const std::string& addressHex, int value);
        bool WriteMemory(DWORD_PTR address, float value);
        bool WriteMemory(const std::string& addressHex, float value);
        bool WriteMemory(DWORD_PTR address, long value);
        bool WriteMemory(const std::string& addressHex, long value);

        static DWORD_PTR HexStringToAddress(const std::string& hexStr);

        bool IsProcessOpen() const { return m_proc.Handle != nullptr; }
        
        Proc& GetProc() { return m_proc; }
        const Proc& GetProc() const { return m_proc; }

    private:
        Proc m_proc;

        struct PatternData {
            std::vector<BYTE> pattern;
            std::vector<BYTE> mask;
        };
        PatternData ParsePattern(const std::string& patternStr);

        int FindPatternInBuffer(const BYTE* buffer, size_t bufferSize, const PatternData& patternData, int startOffset = 0);

        bool IsValidMemoryRegion(DWORD_PTR address, size_t size, bool writable, bool executable);
    };
}

