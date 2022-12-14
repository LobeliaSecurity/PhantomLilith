import phantomlilith.modules.debugger
import phantomlilith.modules.walker
import phantomlilith.modules.util
import phantomlilith.defines
import traceback
import ctypes


class SoftwareBreakpointInjector(phantomlilith.modules.debugger.Engine):
    def __init__(self) -> None:
        super().__init__()
        self.memoryWalker = phantomlilith.modules.walker.MemoryWalker()
        self.injections = {}

    def __del__(self):
        self.detach()

    def run(self, pid):
        if(self.attach(pid)):
            self.memoryWalker.openProcess(pid)
            print("[CTRL + C] -> Exit.")
            try:
                self.debugLoop()
            except KeyboardInterrupt:
                print(
                    "SoftwareBreakpointInjector:",
                    "Leaving..."
                )

    def onCreateProcess(self):
        super().onCreateProcess()
        self.injector()

    def onBreakpoint(self):
        exceptionAddress = int(
            self.lpDebugEvent.u.Exception.ExceptionRecord.ExceptionAddress
        )
        if(exceptionAddress in self.injections):
            try:
                hThread = phantomlilith.modules.util.openThread(
                    self.lpDebugEvent.dwThreadId)
                if(hThread):
                    thread_context = phantomlilith.modules.util.getThreadContext(
                        hThread
                    )
                    if(thread_context):
                        thread_context.Rip -= 0x01
                        self.injections[exceptionAddress](
                            ctypes.pointer(thread_context).contents
                        )
                        phantomlilith.modules.util.setThreadContext(
                            hThread, thread_context)
                    phantomlilith.modules.util.closeHandle(hThread)
                self.memoryWalker.write(
                    exceptionAddress, self.memoryWalker.changeHistory[exceptionAddress][0], noLogging=True
                )
            except:
                traceback.print_exc()

            ctypes.windll.kernel32.ContinueDebugEvent(
                self.lpDebugEvent.dwProcessId,
                self.lpDebugEvent.dwThreadId,
                phantomlilith.defines.ContinueStatus.DBG_CONTINUE
            )
            self.memoryWalker.write(exceptionAddress, b"\xCC", noLogging=True)
            return None
        else:
            return phantomlilith.defines.ContinueStatus.DBG_EXCEPTION_NOT_HANDLED

    def set(self, address: int):
        def _setInjection(func):
            self.injections[address] = func
        return _setInjection

    def injector(self):
        for inject_address in self.injections:
            print(
                "SoftwareBreakpointInjector:",
                f"Setting injection at: {hex(inject_address)} {self.injections[inject_address].__name__}"
            )
            if(self.memoryWalker.write(inject_address, b"\xCC")):
                print(" -> Success")
            else:
                print(" -> Failed")


class JmpInjector():
    def __init__(self) -> None:
        pass

    def inject(self, inject_address, return_address, binary_code):
        # 48BA 0000000000000000 mov r10, < JMP Address >
        # 41FF E2 jmp r10
        # ~
        # 48BA 0000000000000000 mov r10, < Inject Address >
        # 41FF E2 jmp r10
        pass
