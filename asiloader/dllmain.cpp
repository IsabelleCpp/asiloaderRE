// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "fakedinput.h"

typedef unsigned long long QWORD;

bool ValidExecutableName = false;

int vsprintf_s_0x400(char* buffer, const char* format, ...)
{
    va_list ArgList; // [rsp+40h] [rbp+18h] BYREF

    va_start(ArgList, format);
    return vsprintf_s(buffer, 0x400ui64, format, ArgList);
}

void ConcRT_DumpMessage(const char* format, ...)
{
    static std::string Message_String_Glob;
    const char* String_Data; // rdx
    FILE* Stream; // [rsp+20h] [rbp-828h] BYREF
    char Buffer[1024]; // [rsp+30h] [rbp-818h] BYREF
    CHAR OutputString[1024]; // [rsp+430h] [rbp-418h] BYREF
    va_list va; // [rsp+858h] [rbp+10h] BYREF

    va_start(va, format);
    if (ValidExecutableName)
    {
        vsprintf_s(Buffer, sizeof(Buffer), format, va);
        vsprintf_s_0x400(OutputString, "%s\n", Buffer);
        OutputDebugStringA(OutputString);
        Message_String_Glob.append(Buffer);
        Message_String_Glob.append("\n");
        if (!fopen_s(&Stream, "asiloader.log", "w"))
        {
            String_Data = Message_String_Glob.c_str();
            fprintf(Stream, String_Data);
            fflush(Stream);
            fclose(Stream);
        }
    }
}

int vsprintf_s_MAX_PATH(char* const Buffer, const char* const Format, ...)
{
    va_list ArgList; // [rsp+40h] [rbp+18h] BYREF

    va_start(ArgList, Format);
    return vsprintf_s(Buffer, MAX_PATH, Format, ArgList);
}

void __stdcall HookFakeDllExports()
{
    HMODULE hdinput8; // rdi
    QWORD DirectInput8Create; // rbx
    QWORD DllCanUnloadNow; // rbx
    QWORD DllGetClassObject ; // rbx
    QWORD DllRegisterServer; // rbx
    QWORD DllUnregisterServer; // rbx
    DWORD flOldProtect; // [rsp+20h] [rbp-248h] BYREF
    CHAR SystemDirectory[MAX_PATH]; // [rsp+30h] [rbp-238h] BYREF
    CHAR dinput8_dll[MAX_PATH]; // [rsp+140h] [rbp-128h] BYREF

    memset(SystemDirectory, 0, sizeof(SystemDirectory));
    GetSystemDirectoryA(SystemDirectory, 0x104u);
    vsprintf_s_MAX_PATH(dinput8_dll, "%s\\%s", SystemDirectory, "dinput8.dll");
    hdinput8 = LoadLibraryA(dinput8_dll);
    ConcRT_DumpMessage("LIB: \"%s\" => %016llX", dinput8_dll, hdinput8);
    VirtualProtect(::DirectInput8Create, 0x10ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    DirectInput8Create = (QWORD)GetProcAddress(hdinput8, "DirectInput8Create");
    ConcRT_DumpMessage("API: \"%s\" => %016llX", "DirectInput8Create", DirectInput8Create);
    *(WORD*)::DirectInput8Create = 0xB848;
    *(QWORD*)((char*)::DirectInput8Create + 2) = DirectInput8Create;
    *((WORD*)::DirectInput8Create + 5) = 0xC350;
    VirtualProtect(::DirectInput8Create, 0x10ui64, flOldProtect, &flOldProtect);
    VirtualProtect(::DllCanUnloadNow, 0x10ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    DllCanUnloadNow = (QWORD)GetProcAddress(hdinput8, "DllCanUnloadNow");
    ConcRT_DumpMessage("API: \"%s\" => %016llX", "DllCanUnloadNow", DllCanUnloadNow);
    *(WORD*)::DllCanUnloadNow = 0xB848;
    *(QWORD*)((char*)::DllCanUnloadNow + 2) = DllCanUnloadNow;
    *((WORD*)::DllCanUnloadNow + 5) = 0xC350;
    VirtualProtect(::DllCanUnloadNow, 0x10ui64, flOldProtect, &flOldProtect);
    VirtualProtect(::DllGetClassObject, 0x10ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    DllGetClassObject = (QWORD)GetProcAddress(
        hdinput8,
        "DllGetClassObject");
    ConcRT_DumpMessage("API: \"%s\" => %016llX", "DllGetClassObject", DllGetClassObject);
    *(WORD*)::DllGetClassObject = 0xB848;
    *(QWORD*)((char*)::DllGetClassObject + 2) = DllGetClassObject;
    *((WORD*)::DllGetClassObject + 5) = 0xC350;
    VirtualProtect(::DllGetClassObject, 0x10ui64, flOldProtect, &flOldProtect);
    VirtualProtect(::DllRegisterServer, 0x10ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    DllRegisterServer = (QWORD)GetProcAddress(hdinput8, "DllRegisterServer");
    ConcRT_DumpMessage("API: \"%s\" => %016llX", "DllRegisterServer", DllRegisterServer);
    *(WORD*)::DllRegisterServer = 0xB848;
    *(QWORD*)((char*)::DllRegisterServer + 2) = DllRegisterServer;
    *((WORD*)::DllRegisterServer + 5) = 0xC350;
    VirtualProtect(::DllRegisterServer, 0x10ui64, flOldProtect, &flOldProtect);
    VirtualProtect(::DllUnregisterServer, 0x10ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    DllUnregisterServer = (QWORD)GetProcAddress(hdinput8, "DllUnregisterServer");
    ConcRT_DumpMessage("API: \"%s\" => %016llX", "DllUnregisterServer", DllUnregisterServer);
    *(WORD*)::DllUnregisterServer = 0xB848;
    *(QWORD*)((char*)::DllUnregisterServer + 2) = DllUnregisterServer;
    *((WORD*)::DllUnregisterServer + 5) = 0xC350;
    VirtualProtect(::DllUnregisterServer, 0x10ui64, flOldProtect, &flOldProtect);
}

void ASI_LOADER()
{
    unsigned __int64 cc; // rax
    HANDLE hFirstFileA; // rbx
    HMODULE ASI_PluginAddr_1; // rax
    HANDLE hFirstFile; // rbx
    HMODULE ASI_PluginAddr; // rax
    struct _WIN32_FIND_DATAA FileData; // [rsp+20h] [rbp-E0h] BYREF
    char GamePath[272]; // [rsp+160h] [rbp+60h] BYREF
    CHAR ASI_Plugin_Path[272]; // [rsp+270h] [rbp+170h] BYREF
    CHAR Plugins_Buffer[272]; // [rsp+380h] [rbp+280h] BYREF
    char asi_folder[272]; // [rsp+490h] [rbp+390h] BYREF

    ConcRT_DumpMessage("LOADER: Loading *.asi plugins");
    memset(GamePath, 0, 0x104ui64);
    GetModuleFileNameA(0i64, GamePath, 0x104u);
    cc = -1i64;
    do
        ++cc;
    while (GamePath[cc]);
    if (cc)
    {
        while (GamePath[cc] != '\\')
        {
            if (!--cc)
                goto GameDirFound;
        }
        if (cc >= 0x104)
        {
            __fastfail(FAST_FAIL_RANGE_CHECK_FAILURE);
        }
        GamePath[cc] = 0;
    }
GameDirFound:
    vsprintf_s_MAX_PATH(Plugins_Buffer, "%s\\*.asi", GamePath);
    hFirstFileA = FindFirstFileA(Plugins_Buffer, &FileData);
    if (hFirstFileA != (HANDLE)-1i64)
    {
        do
        {
            vsprintf_s_MAX_PATH(ASI_Plugin_Path, "%s\\%s", GamePath, FileData.cFileName);
            ConcRT_DumpMessage("ASI: Loading \"%s\"", ASI_Plugin_Path);
            ASI_PluginAddr_1 = LoadLibraryA(ASI_Plugin_Path);
            if (ASI_PluginAddr_1)
                ConcRT_DumpMessage("     \"%s\" => %016llX", FileData.cFileName, ASI_PluginAddr_1);
            else
                ConcRT_DumpMessage("     \"%s\" failed to load", FileData.cFileName);
        } while (FindNextFileA(hFirstFileA, &FileData));
        FindClose(hFirstFileA);
    }
    vsprintf_s_MAX_PATH(asi_folder, "%s\\asi", GamePath);
    vsprintf_s_MAX_PATH(Plugins_Buffer, "%s\\*.asi", asi_folder);
    hFirstFile = FindFirstFileA(Plugins_Buffer, &FileData);
    if (hFirstFile != (HANDLE)-1i64)
    {
        do
        {
            vsprintf_s_MAX_PATH(ASI_Plugin_Path, "%s\\%s", asi_folder, FileData.cFileName);
            ConcRT_DumpMessage("ASI: Loading \"%s\"", ASI_Plugin_Path);
            ASI_PluginAddr = LoadLibraryA(ASI_Plugin_Path);
            if (ASI_PluginAddr)
                ConcRT_DumpMessage("     \"%s\" => %016llX", FileData.cFileName, ASI_PluginAddr);
            else
                ConcRT_DumpMessage("     \"%s\" failed to load", FileData.cFileName);
        } while (FindNextFileA(hFirstFile, &FileData));
        FindClose(hFirstFile);
    }
    ConcRT_DumpMessage("LOADER: Finished loading *.asi plugins");
}

void __fastcall ASI_LOADER_MAIN(struct _FILETIME* a1)
{
    static bool ASI_LOADED = false;
    if (!ASI_LOADED)
    {
        ASI_LOADED = true;
        ASI_LOADER();
    }
    GetSystemTimeAsFileTime(a1);
}

__int64 __stdcall ASI_LOADER_HOOK(__int64 MainModAddr)
{
    unsigned int* ImportDataDir; // r14
    unsigned int ImportNameTable_RVA; // eax
    int i; // edi
    __int64* ImportNameTable; // rbx
    __int64 IAT; // r15
    __int64 INT_entry; // rax
    __int64* IAT_GetSystemTimeAsFileTime; // rdi
    __int64 OriginalAddr; // rbx
    DWORD flOldProtect_1; // r8d
    DWORD flOldProtect; // [rsp+58h] [rbp+20h] BYREF

    ImportDataDir = (unsigned int*)(MainModAddr + *(unsigned int*)(*(int*)(MainModAddr + 0x3C) + MainModAddr + 0x90));
    ImportNameTable_RVA = *ImportDataDir;
    if (!*ImportDataDir)
        return 0i64;
    while (1)
    {
        i = 0;
        ImportNameTable = (__int64*)(MainModAddr + ImportNameTable_RVA);
        IAT = MainModAddr + ImportDataDir[4];
        INT_entry = *ImportNameTable;
        if (*ImportNameTable)
            break;
    NextEntry:
        ImportNameTable_RVA = ImportDataDir[5];
        ImportDataDir += 5;
        if (!ImportNameTable_RVA)
            return 0i64;
    }
    while (!((INT_entry & 0x8000000000000000ui64) != 0
        ? (WORD)INT_entry == 0xFFFF
        : strcmp((const char*)(INT_entry + MainModAddr + 2), "GetSystemTimeAsFileTime") == 0))
    {
        INT_entry = ImportNameTable[1];
        ++ImportNameTable;
        ++i;
        if (!INT_entry)
            goto NextEntry;
    }
    IAT_GetSystemTimeAsFileTime = (__int64*)(IAT + 8i64 * i);
    VirtualProtect(IAT_GetSystemTimeAsFileTime, 8ui64, PAGE_EXECUTE_READWRITE, &flOldProtect);
    OriginalAddr = *IAT_GetSystemTimeAsFileTime;
    flOldProtect_1 = flOldProtect;
    *IAT_GetSystemTimeAsFileTime = (__int64)ASI_LOADER_MAIN;
    VirtualProtect(IAT_GetSystemTimeAsFileTime, 8ui64, flOldProtect_1, &flOldProtect);
    return OriginalAddr;
}

void LoaderInit()
{
    __int64 ProccessMainModule; // rax
    DWORD ExportDirectory_rva; // edx
    unsigned int Name_rva; // edx
    const char* ProcessMainModuleName; // rbx
    __int64 cc; // rax
    QWORD ModuleHandleA; // rax
    char Filename[MAX_PATH]; // [rsp+20h] [rbp-128h] BYREF

    ProccessMainModule = (__int64)GetModuleHandleA(0i64);
    ExportDirectory_rva = *(unsigned int*)(*(int*)(ProccessMainModule + 0x3C) + ProccessMainModule + 0x88);
    if (!ExportDirectory_rva
        || (Name_rva = *(DWORD*)(ExportDirectory_rva + ProccessMainModule + 0xC)) == 0
        || (ProcessMainModuleName = (const char*)(ProccessMainModule + Name_rva)) == 0i64)
    {
        memset(Filename, 0, sizeof(Filename));
        GetModuleFileNameA(0i64, Filename, sizeof(Filename));
        cc = -1i64;
        do
            ++cc;
        while (Filename[cc]);
        if (!cc)
        {
            HookFakeDllExports();
            return;
        }
        while (Filename[cc - 1] != '\\')
        {
            if (!--cc)
            {
                HookFakeDllExports();
                return;
            }
        }
        ProcessMainModuleName = &Filename[cc];
        if (!&Filename[cc])
        {
            HookFakeDllExports();
            return;
        }
    }
    if (!_stricmp(ProcessMainModuleName, "RDR2.exe") || !_stricmp(ProcessMainModuleName, "game_win64_master.exe"))
    {
        ValidExecutableName = true;
        ConcRT_DumpMessage("// RDR 2 ASI LOADER (build %s)", "Jul 18 2021");
        ConcRT_DumpMessage("//     (C) Alexander Blade 2019-2021");
        HookFakeDllExports();
        ModuleHandleA = (QWORD)GetModuleHandleA(0i64);
        if (!ASI_LOADER_HOOK(ModuleHandleA))
            ConcRT_DumpMessage("FATAL: Init failed!");
    }
    else
    {
        HookFakeDllExports();
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    static bool LoaderInited = false;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH && !LoaderInited)
    {
        LoaderInit();
        LoaderInited = true;
    }
    return TRUE;
}

