import ctypes
import ctypes.wintypes
import phantomlilith.defines
import phantomlilith.structs


class LibraryInformation():
    def __init__(self) -> None:
        self.lpBaseOfDll = None


class ProcessInformation():
    def __init__(self) -> None:
        self.pid = None
        self.fileName = None
        self.dwProcessId = None
        self.hProcess = None
        self.hFile = None
        self.entryPoint = None
        self.lpBaseOfImage = None
        self.hThread = None
        self.dwThreadId = None
        self.lpStartAddress = None
        self.lpThreadLocalBase = None
        # thread id : ProcessInformation
        self.threads = {}
        # base of dll : LibraryInformation
        self.libraries = {}


class Core:
    def __init__(self) -> None:
        self.lpDebugEvent = None
        self.debugProcessInformation = ProcessInformation()
        self.continueDebugging = True
        self.debugAttachedToProcess = False

    def attach(self, pid):
        if(ctypes.windll.kernel32.DebugActiveProcess(pid)):
            self.debugProcessInformation.dwProcessId = pid
            self.debugAttachedToProcess = True
            return True
        return False

    def detach(self):
        self.continueDebugging = False
        return ctypes.windll.kernel32.DebugActiveProcessStop(self.debugProcessInformation.dwProcessId)

    def waitForDebugEvent(self):
        while(self.continueDebugging):
            self.lpDebugEvent = phantomlilith.structs.DEBUG_EVENT()
            if(not ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(self.lpDebugEvent), 100)):
                if(ctypes.windll.kernel32.WaitForSingleObject(self.debugProcessInformation.hProcess, 0) == phantomlilith.defines.TimeoutInterval.WAIT_OBJECT_0):
                    self.lpDebugEvent.dwDebugEventCode = phantomlilith.defines.DebugEventCodes.EXIT_PROCESS_DEBUG_EVENT
                    self.lpDebugEvent.dwProcessId = self.debugProcessInformation.dwProcessId
                    self.lpDebugEvent.dwThreadId = self.debugProcessInformation.dwThreadId
                    if(not ctypes.windll.kernel32.GetExitCodeProcess(self.debugProcessInformation.hProcess, ctypes.byref(self.lpDebugEvent.u.ExitProcess.dwExitCode))):
                        self.lpDebugEvent.u.ExitProcess.dwExitCode = 0xFFFFFFFF
                else:
                    # Regular timeout
                    continue

            yield self.lpDebugEvent


class ExceptionEventHandler():
    def __init__(self) -> None:
        self.__exceptionEventHandlers__ = {
            phantomlilith.defines.StatusCodes.STATUS_BREAKPOINT: self.onBreakpoint,
            phantomlilith.defines.StatusCodes.STATUS_SINGLE_STEP: self.onSingleStep,
            phantomlilith.defines.StatusCodes.STATUS_GUARD_PAGE_VIOLATION: self.onGuardPageViolation,
            phantomlilith.defines.StatusCodes.STATUS_ACCESS_VIOLATION: self.onAccessViolation,
            phantomlilith.defines.StatusCodes.STATUS_ILLEGAL_INSTRUCTION: self.onIllegalInstruction,
            phantomlilith.defines.StatusCodes.STATUS_NONCONTINUABLE_EXCEPTION: self.onNoncontinuableException,
            phantomlilith.defines.StatusCodes.STATUS_ARRAY_BOUNDS_EXCEEDED: self.onArrayBoundsExceeded,
            phantomlilith.defines.StatusCodes.STATUS_FLOAT_DENORMAL_OPERAND: self.onFloatDenormalOperand,
            phantomlilith.defines.StatusCodes.STATUS_FLOAT_DIVIDE_BY_ZERO: self.onFloatDivideByZero,
            phantomlilith.defines.StatusCodes.STATUS_INTEGER_DIVIDE_BY_ZERO: self.onIntegarDivideByZero,
            phantomlilith.defines.StatusCodes.STATUS_INTEGER_OVERFLOW: self.onIntegerOverflow,
            phantomlilith.defines.StatusCodes.STATUS_PRIVILEGED_INSTRUCTION: self.onPrivilegedInstruction,
        }

    def onBreakpoint(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onSingleStep(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onGuardPageViolation(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onAccessViolation(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onIllegalInstruction(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onNoncontinuableException(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onArrayBoundsExceeded(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onFloatDenormalOperand(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onFloatDivideByZero(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onIntegarDivideByZero(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onIntegerOverflow(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onPrivilegedInstruction(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def onUnknownException(self):
        return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED


class DebugEventHandler(ExceptionEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self.__debugEventHandlers__ = {
            phantomlilith.defines.DebugEventCodes.EXCEPTION_DEBUG_EVENT: self.onException,
            phantomlilith.defines.DebugEventCodes.CREATE_THREAD_DEBUG_EVENT: self.onCreateThread,
            phantomlilith.defines.DebugEventCodes.CREATE_PROCESS_DEBUG_EVENT: self.onCreateProcess,
            phantomlilith.defines.DebugEventCodes.EXIT_THREAD_DEBUG_EVENT: self.onExitThread,
            phantomlilith.defines.DebugEventCodes.EXIT_PROCESS_DEBUG_EVENT: self.onExitProcess,
            phantomlilith.defines.DebugEventCodes.LOAD_DLL_DEBUG_EVENT: self.onLoadDll,
            phantomlilith.defines.DebugEventCodes.UNLOAD_DLL_DEBUG_EVENT: self.onUnloadDll,
            phantomlilith.defines.DebugEventCodes.OUTPUT_DEBUG_STRING_EVENT: self.onOutputDebugString,
            phantomlilith.defines.DebugEventCodes.RIP_EVENT: self.onRip,
        }

    def onException(self):
        continue_status = phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED
        try:
            continue_status = self.__exceptionEventHandlers__[
                self.lpDebugEvent.u.Exception.ExceptionRecord.ExceptionCode]()
        except:
            continue_status = self.onUnknownException()
        if(continue_status):
            ctypes.windll.kernel32.ContinueDebugEvent(
                self.lpDebugEvent.dwProcessId,
                self.lpDebugEvent.dwThreadId,
                continue_status
            )

    def onCreateThread(self):
        threadInformation = ProcessInformation()
        threadInformation.dwThreadId = self.lpDebugEvent.dwThreadId
        threadInformation.hThread = self.lpDebugEvent.u.CreateProcessInfo.hThread
        threadInformation.lpStartAddress = self.lpDebugEvent.u.CreateProcessInfo.lpStartAddress
        threadInformation.lpThreadLocalBase = self.lpDebugEvent.u.CreateProcessInfo.lpThreadLocalBase
        self.debugProcessInformation.threads[
            self.lpDebugEvent.dwThreadId
        ] = threadInformation

        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)

    def onCreateProcess(self):
        if(not self.debugProcessInformation.hFile):
            self.debugProcessInformation.entryPoint = self.lpDebugEvent.u.CreateProcessInfo.lpStartAddress
            self.debugProcessInformation.hFile = self.lpDebugEvent.u.CreateProcessInfo.hFile
            self.debugProcessInformation.lpBaseOfImage = self.lpDebugEvent.u.CreateProcessInfo.lpBaseOfImage
            if(self.debugAttachedToProcess):
                self.debugProcessInformation.hProcess = self.lpDebugEvent.u.CreateProcessInfo.hProcess
                self.debugProcessInformation.hThread = self.lpDebugEvent.u.CreateProcessInfo.hThread
                self.debugProcessInformation.dwThreadId = None

            threadInformation = ProcessInformation()
            threadInformation.hFile = self.lpDebugEvent.u.CreateProcessInfo.hFile
            threadInformation.hProcess = self.lpDebugEvent.u.CreateProcessInfo.hProcess
            threadInformation.hThread = self.lpDebugEvent.u.CreateProcessInfo.hThread
            threadInformation.dwProcessId = self.lpDebugEvent.dwProcessId
            threadInformation.dwThreadId = self.lpDebugEvent.dwThreadId
            threadInformation.lpBaseOfImage = self.lpDebugEvent.u.CreateProcessInfo.lpBaseOfImage
            threadInformation.lpStartAddress = self.lpDebugEvent.u.CreateProcessInfo.lpStartAddress
            threadInformation.lpThreadLocalBase = self.lpDebugEvent.u.CreateProcessInfo.lpThreadLocalBase
            self.debugProcessInformation.threads[
                self.lpDebugEvent.dwThreadId
            ] = threadInformation

        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_CONTINUE)

    def onExitThread(self):
        del self.debugProcessInformation.threads[self.lpDebugEvent.dwThreadId]
        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)

    def onExitProcess(self):
        if(self.lpDebugEvent.dwProcessId == self.debugProcessInformation.dwProcessId):
            self.continueDebugging = False
        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_CONTINUE)

    def onLoadDll(self):
        libraryInformation = LibraryInformation()
        libraryInformation.lpBaseOfDll = self.lpDebugEvent.u.LoadDll.lpBaseOfDll

        self.debugProcessInformation.libraries[
            self.lpDebugEvent.u.LoadDll.lpBaseOfDll
        ] = libraryInformation

        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)

    def onUnloadDll(self):
        del self.debugProcessInformation.libraries[
            self.lpDebugEvent.u.UnloadDll.lpBaseOfDll
        ]
        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)

    def onOutputDebugString(self):
        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)

    def onRip(self):
        ctypes.windll.kernel32.ContinueDebugEvent(
            self.lpDebugEvent.dwProcessId,
            self.lpDebugEvent.dwThreadId,
            phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED)


class Engine(Core, DebugEventHandler):
    def __init__(self) -> None:
        super(Engine, self).__init__()
        super(Core, self).__init__()
        super(DebugEventHandler, self).__init__()

    def debugLoop(self):
        for lpDebugEvent in self.waitForDebugEvent():
            self.__debugEventHandlers__[
                lpDebugEvent.dwDebugEventCode
            ]()
