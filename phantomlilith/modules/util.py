import os
import ctypes
import ctypes.wintypes
import phantomlilith.defines
import phantomlilith.structs


def openProcess(dwDesiredAccess, bInheritHandle, dwProcessId) -> int:
    return ctypes.windll.kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)


def closeHandle(hProcess) -> int:
    return ctypes.windll.kernel32.CloseHandle(hProcess)


def getProcessImageFileNameA(hProcess) -> str:
    R = ""
    lpImageFileName = (ctypes.c_char*256)()
    if(ctypes.windll.psapi.GetProcessImageFileNameA(hProcess, lpImageFileName, ctypes.sizeof(lpImageFileName))):
        R = os.path.basename(lpImageFileName.value).decode()
    return R


def getProcessImageFileName(pid) -> str:
    R = ""
    hProcess = openProcess(phantomlilith.defines.DesiredAccess.PROCESS_QUERY_INFORMATION |
                           phantomlilith.defines.DesiredAccess.PROCESS_VM_READ, False, pid)
    if(hProcess):
        R = getProcessImageFileNameA(hProcess)
        closeHandle(hProcess)
    return R


def openThread(dwThreadId):
    return ctypes.windll.kernel32.OpenThread(phantomlilith.defines.DesiredAccess.THREAD_ALL_ACCESS, None, dwThreadId)


def getThreadContext(hThread):
    lpContext = phantomlilith.structs.CONTEXT()
    lpContext.ContextFlags = phantomlilith.defines.ContextFlags.CONTEXT_ALL
    ctypes.windll.kernel32.GetThreadContext(hThread, ctypes.byref(lpContext))
    return lpContext


def setThreadContext(hThread, lpContext):
    return ctypes.windll.kernel32.SetThreadContext(hThread, ctypes.byref(lpContext))


def getProcessList() -> dict:
    processList = {}
    lpidProcess = (ctypes.wintypes.DWORD*1024)()
    cb = ctypes.sizeof(lpidProcess)
    lpcbNeeded = ctypes.wintypes.DWORD()

    if(ctypes.windll.psapi.EnumProcesses(
            ctypes.byref(lpidProcess),
            cb, ctypes.byref(lpcbNeeded))
       ):
        for i in range(int(lpcbNeeded.value / ctypes.sizeof(ctypes.wintypes.DWORD))):
            pid = lpidProcess[i]
            filename = getProcessImageFileName(pid)
            if(filename not in processList):
                processList[filename] = []
            processList[filename].append({"PID": pid})
    return processList


def readProcessMemory(hProcess, read_address, read_length):
    R = ""
    lpBaseAddress = ctypes.wintypes.LPVOID(read_address)
    lpBuffer = ctypes.create_string_buffer(b'', read_length)
    nSize = read_length
    lpNumberOfBytesRead = ctypes.wintypes.SIZE(0)
    if(ctypes.windll.kernel32.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesRead))):
        R = lpBuffer.raw
    return R


def writeProcessMemory(hProcess, write_address, write_data):
    lpBaseAddress = ctypes.c_ulonglong(write_address)
    lpNumberOfBytesWritten = ctypes.wintypes.SIZE(0)
    lpBuffer = ctypes.c_char_p(write_data)
    nSize = len(write_data)
    if(ctypes.windll.kernel32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(lpNumberOfBytesWritten))):
        return True
    else:
        return False
