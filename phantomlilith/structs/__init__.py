# TODO Separate sources for each header file or make them all the same object?

import ctypes
import ctypes.wintypes
import phantomlilith.defines


class Structure(ctypes.Structure):
    def getDict(self):
        return {name: self.__getattribute__(name) for name, type in self._fields_}


class LUID(Structure):
    _fields_ = [
        ("LowPart", ctypes.wintypes.DWORD),
        ("HighPart", ctypes.wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", ctypes.wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", ctypes.wintypes.DWORD),
        (
            "Privileges",
            LUID_AND_ATTRIBUTES * phantomlilith.defines.AnysizeArray.ANYSIZE_ARRAY,
        ),
    ]


class EXCEPTION_RECORD(Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", ctypes.wintypes.DWORD),
    ("ExceptionFlags", ctypes.wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", ctypes.wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15),
]


class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", ctypes.wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", ctypes.c_void_p),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.wintypes.DWORD),
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", ctypes.wintypes.DWORD),
        ("nDebugInfoSize", ctypes.wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", ctypes.wintypes.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", ctypes.wintypes.DWORD),
    ]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", ctypes.wintypes.DWORD),
    ]


class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", ctypes.c_void_p),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", ctypes.wintypes.DWORD),
        ("nDebugInfoSize", ctypes.wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", ctypes.wintypes.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
    ]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.wintypes.LPSTR),
        ("fUnicode", ctypes.wintypes.WORD),
        ("nDebugStringLength", ctypes.wintypes.WORD),
    ]


class RIP_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", ctypes.wintypes.DWORD),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


class M128A(Structure):
    _fields_ = [
        ("Low", ctypes.c_ulonglong),
        ("High", ctypes.c_ulonglong),
    ]


class XSAVE_STRUCT(Structure):
    _fields_ = [
        ("ControlWord", ctypes.wintypes.WORD),
        ("StatusWord", ctypes.wintypes.WORD),
        ("TagWord", ctypes.wintypes.BYTE),
        ("Reservedl", ctypes.wintypes.BYTE),
        ("ErrorOpcode", ctypes.wintypes.WORD),
        ("ErrorOffset", ctypes.wintypes.DWORD),
        ("ErrorSelector", ctypes.wintypes.WORD),
        ("Reserved2", ctypes.wintypes.WORD),
        ("DataOffset", ctypes.wintypes.DWORD),
        ("DataSelector", ctypes.wintypes.WORD),
        ("Reserved3", ctypes.wintypes.WORD),
        ("MxCsr", ctypes.wintypes.DWORD),
        ("MxCsr_Mask", ctypes.wintypes.DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", ctypes.wintypes.BYTE * 96),
    ]


class CONTEXT_UNION_STRUCT(Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]


XMM_SAVE_AREA32 = XSAVE_STRUCT


class CONTEXT_UNION(ctypes.Union):
    _fields_ = [("FltSave", XMM_SAVE_AREA32), ("struct", CONTEXT_UNION_STRUCT)]


class CONTEXT(Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.wintypes.DWORD),
        ("MxCsr", ctypes.wintypes.DWORD),
        ("SegCs", ctypes.wintypes.WORD),
        ("SegDs", ctypes.wintypes.WORD),
        ("SegEs", ctypes.wintypes.WORD),
        ("SegFs", ctypes.wintypes.WORD),
        ("SegGs", ctypes.wintypes.WORD),
        ("SegSs", ctypes.wintypes.WORD),
        ("EFlags", ctypes.wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("u", CONTEXT_UNION),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


class MEMORY_BASIC_INFORMATION(Structure):
    BaseAddress: ctypes.wintypes.LPVOID
    AllocationBase: ctypes.wintypes.LPVOID
    AllocationProtect: ctypes.wintypes.DWORD
    PartitionId: ctypes.wintypes.WORD
    RegionSize: ctypes.c_size_t
    State: ctypes.wintypes.DWORD
    Protect: ctypes.wintypes.DWORD
    Type: ctypes.wintypes.DWORD

    _fields_ = [
        ("BaseAddress", ctypes.wintypes.LPVOID),
        ("AllocationBase", ctypes.wintypes.LPVOID),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("PartitionId", ctypes.wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_void_p),
        ("EntryPoint", ctypes.c_void_p),
    ]
