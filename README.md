# PhantomLilith

Windows-64bit user mode debugger using Python standard library and libraries written purely in Python

now 0.0.0 - alpha

<div align="center">

![](https://user-images.githubusercontent.com/31212444/206206394-0ac5fe00-369d-442c-8824-6b214c62d0aa.png)

</div>

## Installation

Install PhantomLilith with pip

```bash
pip install git+https://github.com/LobeliaSecurity/PhantomLilith.git
```

## Example / 0.0.0

```python
import phantomlilith
import ctypes
import re

# SoftwareBreakpointInjector : injector using [int3]
injector = phantomlilith.injector.SoftwareBreakpointInjector()
# MemoryWalker : wrapper for memory. operations read, write, writeHistory, undo all changes
memoryWalker = phantomlilith.walker.MemoryWalker()

# {executable file name:[{"PID":pid}, ... ]}
# yup, we think return JSON-able object are not good idea for (method) getProcessList...
pid = phantomlilith.modules.util.getProcessList()[
    "process.exe"
][0]["PID"]

memoryWalker.openProcess(pid)

########################################################################
# MemoryWalker has memory search method that read memory each call.
# it's Not cool for multiple searches in the same area.
# so if this situation, We recommend you create search method like this.
########################################################################
# (method) read(read_address: int, read_length: int) -> bytes
search_field = memoryWalker.read(
    memoryWalker.processInformation.entryPoint, 0x2000000
)
def search(hex):
    return [
        x.start() + memoryWalker.processInformation.entryPoint
        for x in re.finditer(
            re.escape(bytes.fromhex(hex)),
            search_field
        )
    ][0]
########################################################################

# .set(absolute address)
@injector.set(
    search("FF C9 89 8F 18 02 00 00 48 85 C0 75 0E 48 8B CF E8 2E C5 F6 01")
)
def ignoreSub(CPU):
    # argment(CPU) is an CONTEXT structure
    # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
    # The caller doesn't need the return value.
    CPU.Rax += 1

@injector.set(0x7FF7CDAC0000)
def staticFloat(CPU):
    CPU.u.struct.Xmm7.Low = ctypes.c_uint.from_buffer(
        ctypes.c_float(10000.0)
    ).value

# run SoftwareBreakpointInjector
injector.run(pid)

```

## Why we needed purely Python debugger?

Our desire is to avoid messing up the development environment , without requiring a build for quick changes, Easy to Setup, Easy to Share, Avoid being detected by Windows Defender as much as possible for work.
And importantly, sysadmins usually don't care about having Python installed on your work computer.

(The main reason is simply that we wanted to build our own debugger for fun.)
