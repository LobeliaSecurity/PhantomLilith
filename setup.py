import setuptools
import pathlib

setuptools.setup(
    name="PhantomLilith",
    version="0.0.0",
    author="LobeliaSecurity™",
    description="Windows-64bit user mode debugger using Python standard library and libraries written purely in Python",
    url="https://github.com/LobeliaSecurity/PhantomLilith",
    packages=[
        x.parent.as_posix() for x in pathlib.Path(".").glob("**/__init__.py")
    ],
    python_requires='>=3.10'
)
