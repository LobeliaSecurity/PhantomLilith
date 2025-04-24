import phantomlilith.modules.debugger
import phantomlilith.modules.util
import phantomlilith.defines

import re

import typing
import contextlib


class ChangeHistory(typing.TypedDict):
    address: int
    history: list


class MemoryRegion(typing.TypedDict):
    address: int
    MEMORY_BASIC_INFORMATION: phantomlilith.structs.MEMORY_BASIC_INFORMATION


class RegionWalker:
    def __init__(
        self,
        hProcess,
        MEMORY_BASIC_INFORMATION: phantomlilith.structs.MEMORY_BASIC_INFORMATION,
    ):
        self.hProcess = hProcess
        self.info = MEMORY_BASIC_INFORMATION

    def slice(self, BlockSize=0x900000000):
        counter = 0
        RegionSize = self.info.RegionSize
        while True:
            if RegionSize < 0:
                return
            else:
                if RegionSize < BlockSize:
                    yield RegionSize
                else:
                    yield BlockSize
            RegionSize -= BlockSize
            counter += 1

    def search(self, regex: bytes):
        offset = 0
        for read_size in self.slice():
            search_field = phantomlilith.util.readProcessMemory(
                self.hProcess,
                self.info.BaseAddress + offset,
                read_size,
            )

            for match in re.finditer(regex, search_field):
                yield match.start() + self.info.BaseAddress + offset

            offset += read_size


class ModuleInformation(typing.TypedDict):
    name: str
    MODULEINFO: phantomlilith.structs.MODULEINFO


class MemoryWalker:
    def __init__(self) -> None:
        self.processInformation = phantomlilith.modules.debugger.ProcessInformation()
        self.changeHistory = ChangeHistory()
        self.memoryRegions: list[RegionWalker] = []
        self.moduleInformations = ModuleInformation()

    def __del__(self):
        self.undoAll()
        phantomlilith.modules.util.closeHandle(self.processInformation.hProcess)

    def openProcess(self, pid):
        self.processInformation.pid = pid
        self.processInformation.hProcess = phantomlilith.modules.util.openProcess(
            phantomlilith.defines.DesiredAccess.PROCESS_VM_READ
            | phantomlilith.defines.DesiredAccess.PROCESS_VM_WRITE
            | phantomlilith.defines.DesiredAccess.PROCESS_VM_OPERATION
            | phantomlilith.defines.DesiredAccess.PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        self.memoryRegions = self.getAllMemoryRegions()
        self.moduleInformations = self.getAllModuleInformation()
        self.processInformation.pebBaseAddress = (
            phantomlilith.modules.util.ntQueryInformationProcess(
                self.processInformation.hProcess,
                phantomlilith.defines.ProcessInformationClass.ProcessBasicInformation,
            ).PebBaseAddress
        )
        self.processInformation.entryPoint = int.from_bytes(
            self.read(self.processInformation.pebBaseAddress + 0x10, 6), "little"
        )

    def getAllModuleInformation(self) -> ModuleInformation:
        # module name : phantomlilith.structs.MODULEINFO
        return {
            phantomlilith.util.getModuleFileNameEx(
                self.processInformation.hProcess, hModule
            ).split("\\")[-1]: phantomlilith.util.getModuleInformation(
                self.processInformation.hProcess, hModule
            )
            for hModule in phantomlilith.util.enumProcessModulesEx(
                self.processInformation.hProcess,
                phantomlilith.defines.EnumProcessModulesFilterFlag.LIST_MODULES_ALL,
            )
        }

    def getAllMemoryRegions(
        self,
    ) -> list[RegionWalker]:
        R: list[RegionWalker] = []
        offset = 0x00
        while True:
            memoryBasicInformation = phantomlilith.modules.util.virtualQueryEx(
                self.processInformation.hProcess, offset
            )
            if not memoryBasicInformation:
                break
            if memoryBasicInformation.BaseAddress:
                R.append(
                    RegionWalker(
                        self.processInformation.hProcess, memoryBasicInformation
                    )
                )
            offset = (
                memoryBasicInformation.BaseAddress
                if memoryBasicInformation.BaseAddress != None
                else 0
            ) + (
                memoryBasicInformation.RegionSize
                if memoryBasicInformation.RegionSize != None
                else 0
            )
        return R

    @contextlib.contextmanager
    def switchProtect(self, lpAddress: int, dwSize: int, flNewProtect: int) -> None:
        # with self.switchProtect(...):
        try:
            prev = phantomlilith.modules.util.virtualQueryEx(
                self.processInformation.hProcess, lpAddress
            )
            phantomlilith.modules.util.virtualProtectEx(
                self.processInformation.hProcess, lpAddress, dwSize, flNewProtect
            )
            yield
        finally:
            phantomlilith.modules.util.virtualProtectEx(
                self.processInformation.hProcess, lpAddress, dwSize, prev.Protect
            )

    def undoAll(self) -> None:
        print("MemoryWalker:", f"undoAll {len(self.changeHistory)} positions...")
        for address in self.changeHistory:
            self.write(address, self.changeHistory[address][0], noLogging=True)
        print("MemoryWalker:", "undoAll done")

    def write(self, write_address: int, write_data: bytes, noLogging=False) -> bool:
        before = self.read(write_address, len(write_data))
        if phantomlilith.modules.util.writeProcessMemory(
            self.processInformation.hProcess, write_address, write_data
        ):
            if not noLogging:
                for buffer_index in range(len(before)):
                    if write_address + buffer_index not in self.changeHistory:
                        self.changeHistory[write_address + buffer_index] = []
                    self.changeHistory[write_address + buffer_index].append(
                        (before[buffer_index]).to_bytes(1, "little")
                    )
            return True
        else:
            phantomlilith.modules.util.printLastError()
            return False

    def read(self, read_address: int, read_length: int) -> bytes:
        return phantomlilith.modules.util.readProcessMemory(
            self.processInformation.hProcess, read_address, read_length
        )

    def search(self, start_address: int, search_distance: int, pattern: bytes) -> list:
        return [
            x.start() + start_address
            for x in re.finditer(pattern, self.read(start_address, search_distance))
        ]
