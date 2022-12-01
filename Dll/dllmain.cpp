#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <intrin.h>
#include <Psapi.h>
#include <vector>
#include "3rdParty/MinHook.h"

namespace FileLog
{
    const char* m_Name = "perf_log.txt";

    void Erase()
    {
        FILE* m_File = nullptr;
        fopen_s(&m_File, m_Name, "w");

        if (m_File)
            fclose(m_File);
    }

    void Write(const char* m_String)
    {
        FILE* m_File = nullptr;
        fopen_s(&m_File, m_Name, "a");

        if (m_File)
        {
            fwrite(m_String, sizeof(char), strlen(m_String), m_File);
            fclose(m_File);
        }
    }
}

namespace GameThreads
{
    struct Info_t
    {
        HANDLE m_Handle;
        const char* m_Name;

        Info_t(HANDLE h, const char* n) { m_Handle = h; m_Name = n; }
    };

    std::vector<Info_t> m_List;
}

namespace CreateThreadHook
{
    const char* GetThreadName(void* m_Address)
    {
        uintptr_t m_CurAddress = reinterpret_cast<uintptr_t>(m_Address);

        static bool m_Init = true;
        static uintptr_t m_Start = 0, m_End = 0;

        if (m_Init)
        {
            MODULEINFO m_Info = { 0 };
            if (K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(0), &m_Info, sizeof(MODULEINFO)))
            {
                m_Init  = false;
                m_Start = reinterpret_cast<uintptr_t>(m_Info.lpBaseOfDll);
                m_End   = m_Start + static_cast<uintptr_t>(m_Info.SizeOfImage);
            }
        }

        if (m_CurAddress >= m_Start && m_End >= m_CurAddress)
        {
            const char* m_ThreadName = reinterpret_cast<const char*>(m_CurAddress + 0x4C);
            if (m_ThreadName[0] == '\0' || strstr(m_ThreadName, "Thread"))
                return m_ThreadName;
        }

        return nullptr;
    }

    typedef HANDLE(WINAPI* m_tFunc)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD); m_tFunc m_oFunc;
    HANDLE WINAPI Func(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
    {
        void** m_Callers = (void**)(_AddressOfReturnAddress());

        DWORD m_ID = 0x0;
        HANDLE m_Handle = m_oFunc(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, &m_ID);

        if (lpThreadId)
            *lpThreadId = m_ID;

        if (dwCreationFlags == CREATE_SUSPENDED)
        {
            for (int i = 0; 10 >= i; ++i)
            {
                if (!m_Callers[i]) continue;

                const char* m_Name = GetThreadName(m_Callers[i]);
                if (m_Name)
                {
                    GameThreads::m_List.emplace_back(m_Handle, m_Name);
                    break;
                }
            }
        }

        return m_Handle;
    }
}

DWORD __stdcall MainThread(void* m_Reserved)
{
    /*FileLog::Erase();

    AllocConsole();
    FILE* m_Dummy;
    freopen_s(&m_Dummy, "CONIN$", "r", stdin);
    freopen_s(&m_Dummy, "CONOUT$", "w", stderr);
    freopen_s(&m_Dummy, "CONOUT$", "w", stdout);*/

    MH_Initialize();

    MH_CreateHook(CreateThread, CreateThreadHook::Func, (void**)&CreateThreadHook::m_oFunc);

    MH_EnableHook(MH_ALL_HOOKS);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    while (1)
    {
        for (auto m_Thread : GameThreads::m_List)
        {
            if (strncmp(m_Thread.m_Name, "Job", 3) == 0)  // Job Thread
                SetThreadPriority(m_Thread.m_Handle, THREAD_PRIORITY_ABOVE_NORMAL);
            else if (strncmp(m_Thread.m_Name, "Trial", 5) == 0) // Trial Thread
                SetThreadPriority(m_Thread.m_Handle, THREAD_PRIORITY_IDLE);
        }

        Sleep(5000);
    }

    return 0x0;
}

BOOL __stdcall DllMain(HMODULE m_Module, DWORD m_Reason, void* m_Reserved)
{
    if (m_Reason == DLL_PROCESS_ATTACH)
    {
        CreateThread(0, 0, MainThread, 0, 0, 0);
    }

    return 1;
}

