# PhantomLilith

Windows-64bit user mode debugger using Python standard library and libraries written purely in Python

now 0.0.0 - alpha

<div align="center">

![](https://user-images.githubusercontent.com/31212444/206206394-0ac5fe00-369d-442c-8824-6b214c62d0aa.png)

</div>

## Installation

Install my-project with npm

```bash
  pip install git+https://github.com/LobeliaSecurity/PhantomLilith.git
```

## Example / 0.0.0 / SoftwareBreakpointInjector

```python
import ctypes
import phantomlilith

injector = phantomlilith.injector.SoftwareBreakpointInjector()

# .set(offset from ImageBase)
@injector.set(0x14D376B)
def ignoreSub(CPU):
    CPU.Rax += 1

@injector.set(0x1416C20)
def staticFloat(CPU):
    CPU.u.struct.Xmm7.Low = ctypes.c_uint.from_buffer(
        ctypes.c_float(10000.0)
    ).value

# running process file name (inject to first one)
injector.run("process.exe")

```
