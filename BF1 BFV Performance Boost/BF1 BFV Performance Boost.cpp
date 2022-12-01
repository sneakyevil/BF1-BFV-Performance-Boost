#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#define INRANGE(x, a, b) (x >= a && x <= b) 
#define getBits(x) (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
namespace Memory
{
    uintptr_t ResolveCall(uintptr_t m_Base)
    {
        if (!m_Base) return 0;

        return (m_Base + *reinterpret_cast<int*>(m_Base + 0x1) + 0x5);
    }

    __inline bool FindSignature_IsMatch(const PBYTE pAddress, const PBYTE pPattern, const PBYTE pMask)
    {
        size_t s = 0;
        while (pAddress[s] == pPattern[s] || pMask[s] == (BYTE)'?')
        {
            if (!pMask[++s]) return true;
        }
        return false;
    }

    uintptr_t FindSignature(uintptr_t m_dAddress, uintptr_t m_dSize, const char* m_pSignature)
    {
        size_t m_sLength = strlen(m_pSignature);
        size_t m_sAllocSize = m_sLength >> 1;

        PBYTE m_pPatternAlloc = new BYTE[m_sAllocSize];
        PBYTE m_pMaskAlloc = new BYTE[m_sAllocSize];
        PBYTE m_pPattern = m_pPatternAlloc;
        PBYTE m_pMask = m_pMaskAlloc;

        // Run-Time IDA Sig to Sig & Mask
        m_sLength = 0;
        while (*m_pSignature)
        {
            if (*m_pSignature == ' ') ++m_pSignature;
            if (!*m_pSignature) break;
            if (*(PBYTE)m_pSignature == (BYTE)'\?')
            {
                *m_pPattern++ = 0;
                *m_pMask++ = '?';
                m_pSignature += ((*(PWORD)m_pSignature == (WORD)'\?\?') ? 2 : 1);
            }
            else
            {
                *m_pPattern++ = getByte(m_pSignature);
                *m_pMask++ = 'x';
                m_pSignature += 2;
            }
            ++m_sLength;
        }

        // Find Address
        *m_pMask = 0;
        m_pPattern = m_pPatternAlloc;
        m_pMask = m_pMaskAlloc;

        uintptr_t m_dReturn = 0x0;
        PBYTE m_pAddress = reinterpret_cast<PBYTE>(m_dAddress);
        for (uintptr_t i = 0; m_dSize - m_sLength > i; ++i)
        {
            if (FindSignature_IsMatch(m_pAddress + i, m_pPatternAlloc, m_pMaskAlloc))
            {
                m_dReturn = reinterpret_cast<uintptr_t>(m_pAddress + i);
                break;
            }
        }

        delete[] m_pPatternAlloc;
        delete[] m_pMaskAlloc;
        return m_dReturn;
    }
}

namespace Utils
{
    DWORD FindProcessByName(const char* m_Name)
    {
        HANDLE m_Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (m_Snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 m_ProcessEntry;
            m_ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(m_Snap, &m_ProcessEntry))
            {
                while (Process32Next(m_Snap, &m_ProcessEntry))
                {
                    if (strstr(m_ProcessEntry.szExeFile, m_Name))
                    {
                        CloseHandle(m_Snap);
                        return m_ProcessEntry.th32ProcessID;
                    }

                }
            }

            CloseHandle(m_Snap);
        }

        return 0x0;
    }

    DWORD FindProcessProcessByArray(const char** m_Array, int m_ArraySize, int* m_LastIndex)
    {
        HANDLE m_Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (m_Snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 m_ProcessEntry;
            m_ProcessEntry.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(m_Snap, &m_ProcessEntry))
            {
                while (Process32Next(m_Snap, &m_ProcessEntry))
                {
                    for (int i = 0; m_ArraySize > i; ++i)
                    {
                        if (strstr(m_ProcessEntry.szExeFile, m_Array[i]))
                        {
                            *m_LastIndex = i;
                            CloseHandle(m_Snap);
                            return m_ProcessEntry.th32ProcessID;
                        }
                    }
                }
            }

            CloseHandle(m_Snap);
        }

        return 0x0;
    }

    bool FindProcessModule(HANDLE m_ProcessHandle, const char* m_Name, uintptr_t* m_Base, uintptr_t* m_Size)
    {
        HMODULE m_Modules[1024] = { 0 };
        DWORD m_Needed = 0;

        if (K32EnumProcessModules(m_ProcessHandle, m_Modules, sizeof(m_Modules), &m_Needed))
        {
            for (size_t i = 0; (m_Needed / sizeof(HMODULE)) > i; ++i)
            {
                char m_ModuleName[MAX_PATH];

                if (K32GetModuleBaseNameA(m_ProcessHandle, m_Modules[i], m_ModuleName, sizeof(m_ModuleName))
                    && strstr(m_ModuleName, m_Name))
                {
                    MODULEINFO m_ModuleInfo = { 0 };
                    if (K32GetModuleInformation(m_ProcessHandle, m_Modules[i], &m_ModuleInfo, sizeof(m_ModuleInfo)))
                    {
                        *m_Base = reinterpret_cast<uintptr_t>(m_ModuleInfo.lpBaseOfDll);
                        *m_Size = static_cast<uintptr_t>(m_ModuleInfo.SizeOfImage);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    uintptr_t GetBytesRVA(uintptr_t m_Base, uintptr_t m_Address) { return (m_Address - m_Base); }
}

int main()
{
    SetConsoleTitleA("[BF1 / BFV] Performance Boost");
    printf("[ ! ] Searching for BF1 / BFV process.\n");
    const char* m_ProcessNames[2] = { "bf1.exe", "bfv.exe" };

    DWORD m_ProcessID = 0x0;
    int m_ProcessType = -1;
    while (1)
    {
        m_ProcessID = Utils::FindProcessProcessByArray(m_ProcessNames, 2, &m_ProcessType);
        if (m_ProcessID)
        {
            printf("[ + ] Found game: %s\n\n", (m_ProcessType == 0 ? "Battlefield 1" : "Battlefield V"));
            break;
        }

        Sleep(1000);
    }

    // Set Processes To Idle
    {
        const char* m_List[] = { "EASteamProxy.exe", "Origin.exe" };
        for (const char* m_Name : m_List)
        {
            bool m_SucessfullySet = false;

            DWORD m_IdleProcessID = Utils::FindProcessByName(m_Name);
            if (m_IdleProcessID)
            {
                HANDLE m_IdleProcessHandle = OpenProcess(PROCESS_SET_INFORMATION, 0, m_IdleProcessID);
                if (m_IdleProcessHandle)
                {
                    m_SucessfullySet = (SetPriorityClass(m_IdleProcessHandle, IDLE_PRIORITY_CLASS) == 1);
                    CloseHandle(m_IdleProcessHandle);
                }
            }

            printf("[ + ] Process Priority for %s: %d\n", m_Name, m_SucessfullySet);
        }
    }

    printf("\n");

    HANDLE m_ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, m_ProcessID);
    if (m_ProcessHandle)
    {
        std::string m_CurrentDir(MAX_PATH, '\0');
        m_CurrentDir.resize(GetModuleFileNameA(0, &m_CurrentDir[0], static_cast<DWORD>(m_CurrentDir.size())));
        m_CurrentDir = m_CurrentDir.substr(0, m_CurrentDir.find_last_of("\\/"));

        bool m_PerformanceDLL_Loaded = false;
        {
            std::string m_PerformanceDLL = (m_CurrentDir + "\\PerfBoost.dll");
            void* m_ProcessDLLString = VirtualAllocEx(m_ProcessHandle, 0, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (m_ProcessDLLString && WriteProcessMemory(m_ProcessHandle, m_ProcessDLLString, &m_PerformanceDLL[0], m_PerformanceDLL.size() + 1, nullptr))
                m_PerformanceDLL_Loaded = CreateRemoteThread(m_ProcessHandle, 0, 0, LPTHREAD_START_ROUTINE(LoadLibraryA), m_ProcessDLLString, 0, 0);
        }
        printf("[ + ] Performance DLL: %d\n", m_PerformanceDLL_Loaded);

        Sleep(5000); // Give sometime for the game to unpack and start loadin...

        uintptr_t m_ProcessBase = 0, m_ProcessSize = 0;
        if (Utils::FindProcessModule(m_ProcessHandle, m_ProcessNames[m_ProcessType], &m_ProcessBase, &m_ProcessSize))
        {
            auto ProcessPatchAsm = [&m_ProcessHandle, &m_ProcessBase](uintptr_t m_RVA, unsigned char* m_Bytes, size_t m_Size)
            {
                void* m_Address = reinterpret_cast<void*>(m_ProcessBase + m_RVA);
                DWORD m_OldProtect = 0x0;
                if (VirtualProtectEx(m_ProcessHandle, m_Address, m_Size, PAGE_EXECUTE_READWRITE, &m_OldProtect))
                {
                    bool m_Write = WriteProcessMemory(m_ProcessHandle, m_Address, m_Bytes, m_Size, nullptr);
                    VirtualProtectEx(m_ProcessHandle, m_Address, m_Size, m_OldProtect, &m_OldProtect);
                    return m_Write;
                }

                return false;
            };

            printf("[ + ] Process Priority: %d\n", (SetPriorityClass(m_ProcessHandle, ABOVE_NORMAL_PRIORITY_CLASS) == 1));

            unsigned char* m_ProcessBytes = new unsigned char[m_ProcessSize];
            uintptr_t m_ProcessBytesPtr = reinterpret_cast<uintptr_t>(m_ProcessBytes);
            if (ReadProcessMemory(m_ProcessHandle, reinterpret_cast<void*>(m_ProcessBase), m_ProcessBytes, m_ProcessSize, nullptr))
            {
                uintptr_t m_SecurityCheckCookie = Memory::FindSignature(m_ProcessBytesPtr, m_ProcessSize, "E8 ? ? ? ? 48 8D A5");
                unsigned char m_SecurityCheckCookieBytes[] = { 0xC3 };
                printf("[ + ] Security Check Cookie: %d\n", (m_SecurityCheckCookie ? ProcessPatchAsm(Utils::GetBytesRVA(m_ProcessBytesPtr, Memory::ResolveCall(m_SecurityCheckCookie)), m_SecurityCheckCookieBytes, sizeof(m_SecurityCheckCookieBytes)) : false));

                switch (m_ProcessType) // Maybe add shit later...
                {
                    case 0: // BF1
                    {
                    }
                    break;
                    case 1: // BFV
                    {
                    }
                    break;
                }
            }
            else
                printf("[ ERROR ] Couldn't get process data...\n");

            delete[] m_ProcessBytes;
        }
        else
            printf("[ ERROR ] Couldn't get process base/size...\n");

        CloseHandle(m_ProcessHandle);
    }
    else
        printf("[ ERROR ] Couldn't open process to the game...\n");

    printf("\nProcess will exit in 5 seconds...");
    Sleep(5000);
    return 0;
}