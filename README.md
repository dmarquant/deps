# Deps - Dependency Analyzer for Windows

Deps is a utility for analyzing runtime dependencies (.dlls) for native windows programs or dlls. It scans an executable
or dll for its dependencies and recurses until all dependencies have been analyzed.

## Usage

```
> deps <dll_or_exe>
```

Each dll entry is shown with the path where it was found. Dlls not found are flagged with `missing` and dlls with a 
different architecture are flagged with `arch`.

```
> deps deps.exe
ok       KERNEL32.dll                             C:\Windows\system32\KERNEL32.dll
ok       ntdll.dll                                C:\Windows\system32\ntdll.dll
ok       KERNELBASE.dll                           C:\Windows\system32\KERNELBASE.dll
```

## Building

```
> cl deps.cpp
```

