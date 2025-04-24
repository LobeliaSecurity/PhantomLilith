# TODO: Split files by proper module name

import sys
import os
import ctypes
import ctypes.wintypes
import phantomlilith.defines
import phantomlilith.structs


def openProcess(dwDesiredAccess, bInheritHandle, dwProcessId) -> int:
    return ctypes.windll.kernel32.OpenProcess(
        dwDesiredAccess, bInheritHandle, dwProcessId
    )


def closeHandle(hProcess) -> int:
    return ctypes.windll.kernel32.CloseHandle(hProcess)


def getProcessImageFileNameA(hProcess) -> str:
    R = ""
    lpImageFileName = (ctypes.c_char * 256)()
    if ctypes.windll.psapi.GetProcessImageFileNameA(
        hProcess, lpImageFileName, ctypes.sizeof(lpImageFileName)
    ):
        R = os.path.basename(lpImageFileName.value).decode()
    return R


def getProcessImageFileName(pid) -> str:
    R = ""
    hProcess = openProcess(
        phantomlilith.defines.DesiredAccess.PROCESS_QUERY_INFORMATION
        | phantomlilith.defines.DesiredAccess.PROCESS_VM_READ,
        False,
        pid,
    )
    if hProcess:
        R = getProcessImageFileNameA(hProcess)
        closeHandle(hProcess)
    return R


def openThread(dwThreadId):
    return ctypes.windll.kernel32.OpenThread(
        phantomlilith.defines.DesiredAccess.THREAD_ALL_ACCESS, None, dwThreadId
    )


# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
def getThreadContext(hThread):
    lpContext = phantomlilith.structs.CONTEXT()
    lpContext.ContextFlags = phantomlilith.defines.ContextFlags.CONTEXT_ALL
    ctypes.windll.kernel32.GetThreadContext(hThread, ctypes.byref(lpContext))
    return lpContext


def setThreadContext(hThread, lpContext):
    return ctypes.windll.kernel32.SetThreadContext(hThread, ctypes.byref(lpContext))


def getPidList(lpidProcess_size=1024) -> dict:
    processList = {}
    lpidProcess = (ctypes.wintypes.DWORD * lpidProcess_size)()
    cb = ctypes.sizeof(lpidProcess)
    lpcbNeeded = ctypes.wintypes.DWORD()

    if ctypes.windll.psapi.EnumProcesses(
        ctypes.byref(lpidProcess), cb, ctypes.byref(lpcbNeeded)
    ):
        for i in range(int(lpcbNeeded.value / ctypes.sizeof(ctypes.wintypes.DWORD))):
            pid = lpidProcess[i]
            filename = getProcessImageFileName(pid)
            if filename not in processList:
                processList[filename] = []
            processList[filename].append(pid)
    return processList


def readProcessMemory(hProcess, read_address, read_length):
    R = b""
    lpBaseAddress = ctypes.wintypes.LPVOID(read_address)
    lpBuffer = ctypes.create_string_buffer(b"", read_length)
    nSize = ctypes.c_size_t(read_length)
    lpNumberOfBytesRead = ctypes.wintypes.SIZE(0)
    if ctypes.windll.kernel32.ReadProcessMemory(
        hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead)
    ):
        R = lpBuffer.raw
    return R


def writeProcessMemory(hProcess, write_address, write_data):
    lpBaseAddress = ctypes.c_ulonglong(write_address)
    lpNumberOfBytesWritten = ctypes.wintypes.SIZE(0)
    lpBuffer = ctypes.c_char_p(write_data)
    nSize = len(write_data)
    if ctypes.windll.kernel32.WriteProcessMemory(
        hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesWritten)
    ):
        return True
    else:
        return False


# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
def virtualAlloc(lpAddress, dwSize, flAllocationType, flProtect):
    return ctypes.windll.kernel32.VirtualAlloc(
        ctypes.byref(lpAddress), dwSize, flAllocationType, flProtect
    )


# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
def virtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
    return ctypes.windll.kernel32.VirtualAllocEx(
        hProcess, ctypes.byref(lpAddress), dwSize, flAllocationType, flProtect
    )


# https://learn.microsoft.com/ja-jp/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
def virtualProtect(lpAddress, dwSize, flNewProtect):
    lpflOldProtect = ctypes.wintypes.PDWORD
    ctypes.windll.kernel32.VirtualProtect(
        ctypes.byref(ctypes.wintypes.LPVOID(lpAddress)),
        dwSize,
        ctypes.byref(ctypes.wintypes.LPVOID(flNewProtect)),
        ctypes.byref(lpflOldProtect),
    )
    return lpflOldProtect


# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
def virtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect):
    lpflOldProtect = ctypes.wintypes.LPVOID(0)
    if not ctypes.windll.kernel32.VirtualProtectEx(
        hProcess,
        ctypes.wintypes.LPVOID(lpAddress),
        dwSize,
        flNewProtect,
        ctypes.byref(lpflOldProtect),
    ):
        return None
    return lpflOldProtect


# https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
def virtualQueryEx(hProcess, lpAddress):
    lpBuffer = phantomlilith.structs.MEMORY_BASIC_INFORMATION()
    if ctypes.windll.kernel32.VirtualQueryEx(
        hProcess,
        ctypes.wintypes.LPVOID(lpAddress),
        ctypes.byref(lpBuffer),
        ctypes.sizeof(lpBuffer),
    ) < ctypes.sizeof(lpBuffer):
        return None
    return lpBuffer


# https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess?redirectedfrom=MSDN
def ntQueryInformationProcess(ProcessHandle, ProcessInformationClass):
    ProcessInformation = {
        phantomlilith.defines.ProcessInformationClass.ProcessBasicInformation: phantomlilith.structs.PROCESS_BASIC_INFORMATION
    }[ProcessInformationClass]()
    ctypes.windll.ntdll.NtQueryInformationProcess(
        ProcessHandle,
        ProcessInformationClass,
        ctypes.byref(ProcessInformation),
        ctypes.sizeof(ProcessInformation),
        None,
    )
    return ProcessInformation


def printLastError():
    print(
        phantomlilith.defines.StatusCodes.getStr(ctypes.windll.kernel32.GetLastError())
    )


# https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex
def enumProcessModulesEx(hProcess, dwFilterFlag, lphModule_size=1024):
    lphModule = (ctypes.wintypes.HMODULE * lphModule_size)()
    cbNeeded = ctypes.c_ulong(0)
    ctypes.windll.psapi.EnumProcessModulesEx(
        hProcess,
        ctypes.byref(lphModule),
        ctypes.sizeof(lphModule),
        ctypes.byref(cbNeeded),
        dwFilterFlag,
    )
    return [x for x in lphModule if x != None]


# https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea
def getModuleFileNameEx(hProcess, hModule=None):
    lpFilename = ctypes.create_string_buffer(512)
    ctypes.windll.psapi.GetModuleFileNameExA(
        hProcess,
        ctypes.wintypes.HMODULE(hModule),
        ctypes.byref(lpFilename),
        int(ctypes.sizeof(lpFilename) / ctypes.sizeof(ctypes.wintypes.LPSTR)),
    )
    return lpFilename.value.decode()


# https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation
def getModuleInformation(hProcess, hModule):
    lpmodinfo = phantomlilith.structs.MODULEINFO()
    ctypes.windll.psapi.GetModuleInformation(
        hProcess,
        ctypes.wintypes.HMODULE(hModule),
        ctypes.byref(lpmodinfo),
        ctypes.sizeof(lpmodinfo),
    )
    return lpmodinfo
