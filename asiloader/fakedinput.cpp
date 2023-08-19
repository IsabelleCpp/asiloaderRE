#include "pch.h"
#include "fakedinput.h"

HRESULT __stdcall DirectInput8Create(HINSTANCE, DWORD, const IID* const, LPVOID*, LPVOID*)
{
    auto result = 0xAAAAAAAAAAAAAAAAui64;
    static auto StaticQWORD = result;

    return result;
}

HRESULT __stdcall DllCanUnloadNow()
{
    auto result = 0xAAAAAAAAAAAAAAAAui64;
    static auto StaticQWORD = result;

    return result;
}

HRESULT __stdcall DllGetClassObject(const IID* const, const IID* const, LPVOID*)
{
    auto result = 0xAAAAAAAAAAAAAAAAui64;
    static auto StaticQWORD = result;

    return result;
}

HRESULT __stdcall DllRegisterServer()
{
    auto result = 0xAAAAAAAAAAAAAAAAui64;
    static auto StaticQWORD = result;

    return result;
}

HRESULT __stdcall DllUnregisterServer()
{
    auto result = 0xAAAAAAAAAAAAAAAAui64;
    static auto StaticQWORD = result;

    return result;
}
