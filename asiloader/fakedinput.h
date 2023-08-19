#pragma once
#include "pch.h"

HRESULT __stdcall DirectInput8Create(HINSTANCE, DWORD, const IID* const, LPVOID*, LPVOID*);
HRESULT __stdcall DllCanUnloadNow();
HRESULT __stdcall DllGetClassObject(const IID* const, const IID* const, LPVOID*);
HRESULT __stdcall DllRegisterServer();
HRESULT __stdcall DllUnregisterServer();
