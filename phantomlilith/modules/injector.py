import phantomlilith.modules.debugger
import phantomlilith.modules.util
import phantomlilith.defines
import traceback
import ctypes


class SoftwareBreakpointInjector(phantomlilith.modules.debugger.Engine):
    def __init__(self) -> None:
        super().__init__()
        self.injections = {}
        self.softwareBreakpoints = {}

    def __del__(self):
        self.restoreSoftwareBreakpoints()
        self.detach()

    def run(self, binary_name):
        pid = phantomlilith.modules.util.getProcessList()[
            binary_name
        ][0]["PID"]
        if(self.attach(pid)):
            print("[CTRL + C] -> Exit.")
            try:
                self.debugLoop()
            except KeyboardInterrupt:
                pass

    def onCreateProcess(self):
        super().onCreateProcess()
        self.injector()

    def onBreakpoint(self):
        exceptionAddress = int(
            self.lpDebugEvent.u.Exception.ExceptionRecord.ExceptionAddress
        )
        if(exceptionAddress - self.debugProcessInformation.lpBaseOfImage in self.injections):
            try:
                hThread = phantomlilith.modules.util.openThread(
                    self.lpDebugEvent.dwThreadId)
                if(hThread):
                    thread_context = phantomlilith.modules.util.getThreadContext(
                        hThread)
                    if(thread_context):
                        thread_context.Rip -= 0x01
                        self.injections[
                            exceptionAddress - self.debugProcessInformation.lpBaseOfImage](ctypes.pointer(thread_context).contents)
                        phantomlilith.modules.util.setThreadContext(
                            hThread, thread_context)
                    phantomlilith.modules.util.closeHandle(hThread)

                phantomlilith.modules.util.writeProcessMemory(
                    self.debugProcessInformation.hProcess, exceptionAddress, self.softwareBreakpoints[exceptionAddress])
            except:
                traceback.print_exc()

            ctypes.windll.kernel32.ContinueDebugEvent(
                self.lpDebugEvent.dwProcessId,
                self.lpDebugEvent.dwThreadId,
                phantomlilith.defines.ContinueStatus.DBG_CONTINUE
            )
            phantomlilith.modules.util.writeProcessMemory(
                self.debugProcessInformation.hProcess, exceptionAddress, b"\xCC")
            return None
        else:
            return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def set(self, offset):
        def _setInjection(func):
            self.injections[offset] = func
        return _setInjection

    def injector(self):
        for inject_address in self.injections:
            inject_address += self.debugProcessInformation.lpBaseOfImage
            print(
                f"Setting injection at: {hex(inject_address)} {self.injections[inject_address - self.debugProcessInformation.lpBaseOfImage].__name__}")
            try:
                original_byte = phantomlilith.modules.util.readProcessMemory(
                    self.debugProcessInformation.hProcess, inject_address, 0x1)
                phantomlilith.modules.util.writeProcessMemory(
                    self.debugProcessInformation.hProcess, inject_address, b"\xCC")
                self.softwareBreakpoints[inject_address] = original_byte
                print(" -> Success")
            except:
                print(" -> Failed")
                traceback.print_exc()

    def restoreSoftwareBreakpoints(self):
        for inject_address in self.softwareBreakpoints:
            try:
                print(
                    f"Removing breakpoint at: {hex(inject_address)} {self.injections[inject_address-self.debugProcessInformation.lpBaseOfImage].__name__}")
                phantomlilith.modules.util.writeProcessMemory(
                    self.debugProcessInformation.hProcess, inject_address, self.softwareBreakpoints[inject_address])
                print(" -> Success")
            except:
                print(" -> Failed")
                traceback.print_exc()
