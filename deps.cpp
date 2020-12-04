// References
// - https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
// - https://docs.microsoft.com/en-us/windows/win32/debug/pe-formt
//
// Notes:
// Dll filenames use the local code page. Which means if special characters
// are used in dlls names the exectuable linking it will not be portable to other 
// systems with a different local encoding. The paths to dlls however can contain
// any unicode character.
// 
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <codecvt>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

struct file_mapping
{
    HANDLE File;
    HANDLE Mapping;
    size_t Size;
    uint8_t* Data;
};

file_mapping CreateReadOnlyFileMapping(const wchar_t* Path)
{
    file_mapping FileMapping = {};

    HANDLE File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        return FileMapping;
    }

    LARGE_INTEGER FileSize;
    GetFileSizeEx(File, &FileSize);
    size_t Size = FileSize.QuadPart;

    HANDLE Mapping = CreateFileMappingW(File, NULL, PAGE_READONLY, 0, 0, NULL);
    if (Mapping == INVALID_HANDLE_VALUE)
    {
        CloseHandle(File);
        return FileMapping;
    }

    void* Data = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, Size);
    if (Data == NULL)
    {
        CloseHandle(Mapping);
        CloseHandle(File);
        return FileMapping;
    }

    FileMapping.File = File;
    FileMapping.Mapping = Mapping;
    FileMapping.Size = Size;
    FileMapping.Data = (uint8_t*)Data;
    return FileMapping;
}

void CloseFileMapping(file_mapping* Mapping)
{
    UnmapViewOfFile(Mapping->Data);
    CloseHandle(Mapping->Mapping);
    CloseHandle(Mapping->File);
    memset(Mapping, 0, sizeof(file_mapping));
}


int32_t BinReadI32(uint8_t* Data) {
    int32_t Value;
    memcpy(&Value, Data, sizeof(int32_t));
    return Value;
}

#define ShortSectionNameSize 8

#define MachineTypeAMD64 0x8664
#define MachineTypeI386  0x14c

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_header;

enum {
    DataDirectoryExport     = 0,
    DataDirectoryImport     = 1,
    DataDirectoryResource   = 2,
    DataDirectoryException  = 3,
    DataDirectorySecurity   = 4,
    DataDirectoryBasereloc  = 5,
    DataDirectoryDebug      = 6,
    DataDirectoryCopyright  = 7,
    DataDirectoryGlobalptr  = 8,
    DataDirectoryTls        = 9,
    DataDirectoryLoadConfig = 10,
    DataDirectoryBoundImport = 11,
    DataDirectoryIAT         = 12,
    DataDirectoryDelayImportDescriptor = 13,
    DataDirectoryCLRRuntimeHeader = 14,
    DataDirectoryReserved = 15,
    NumDataDirectories      = 16,
};

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} data_directory;

typedef struct {
    //
    // Standard fields.
    //
    uint16_t  Magic;
    uint8_t   MajorLinkerVersion;
    uint8_t   MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;
    uint32_t   BaseOfCode;
    uint32_t   BaseOfData;

    //
    // NT additional fields.
    //
    uint32_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t  MajorOperatingSystemVersion;
    uint16_t  MinorOperatingSystemVersion;
    uint16_t  MajorImageVersion;
    uint16_t  MinorImageVersion;
    uint16_t  MajorSubsystemVersion;
    uint16_t  MinorSubsystemVersion;
    uint32_t   Reserved1;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t  Subsystem;
    uint16_t  DllCharacteristics;
    uint32_t   SizeOfStackReserve;
    uint32_t   SizeOfStackCommit;
    uint32_t   SizeOfHeapReserve;
    uint32_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;

    data_directory Directories[NumDataDirectories];
} optional_header;

typedef struct {
    //
    // Standard fields.
    //
    uint16_t  Magic;
    uint8_t   MajorLinkerVersion;
    uint8_t   MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;
    uint32_t   BaseOfCode;

    //
    // NT additional fields.
    //
    uint64_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t  MajorOperatingSystemVersion;
    uint16_t  MinorOperatingSystemVersion;
    uint16_t  MajorImageVersion;
    uint16_t  MinorImageVersion;
    uint16_t  MajorSubsystemVersion;
    uint16_t  MinorSubsystemVersion;
    uint32_t   Reserved1;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t  Subsystem;
    uint16_t  DllCharacteristics;
    uint64_t   SizeOfStackReserve;
    uint64_t   SizeOfStackCommit;
    uint64_t   SizeOfHeapReserve;
    uint64_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;

    data_directory Directories[NumDataDirectories];
} optional_header_plus;


typedef struct {
    char Name[ShortSectionNameSize];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} section_header;

typedef struct {
    uint8_t* ImageData;

    coff_header CoffHeader;
    union {
        optional_header      OptionalHeader;
        optional_header_plus OptionalHeaderPlus;
    };

    section_header* SectionHeaders;
} portable_executable;

typedef struct {
    uint32_t ImportLookupTableRVA;
    uint32_t TimeStamp;
    uint32_t ForwaderChain;
    uint32_t NameRVA;
    uint32_t ImportAddressTableRVA;

} import_directory_entry;


void PEInit(portable_executable* PE, uint8_t* Image, int Size) {
    int PEOffset = BinReadI32(Image + 0x3c);

    if (memcmp(Image + PEOffset, "PE\0\0", 4) != 0) {
        printf("WARNING: No pe signature\n");
        return;
    }

    int CoffHeaderOffset = PEOffset + 4;
    memcpy(&PE->CoffHeader, Image + CoffHeaderOffset, sizeof(coff_header));

    int OptionalHeaderOffset = CoffHeaderOffset + sizeof(coff_header);

    uint16_t PEMagic;
    memcpy(&PEMagic, Image + OptionalHeaderOffset, sizeof(uint16_t));

    if (PEMagic == 0x10B) {
        memcpy(&PE->OptionalHeader, Image + OptionalHeaderOffset, sizeof(optional_header));
    } else if (PEMagic == 0x20B) {
        memcpy(&PE->OptionalHeaderPlus, Image + OptionalHeaderOffset, sizeof(optional_header_plus));
    }

    int SectionHeaderOffset = OptionalHeaderOffset + PE->CoffHeader.SizeOfOptionalHeader;
    PE->SectionHeaders = (section_header*)(Image + SectionHeaderOffset);

    PE->ImageData = Image;
}

// Get the section containing an RVA
int PEGetEnclosingSection(portable_executable* PE, uint32_t RVA) {
    for (int Section = 0; Section < PE->CoffHeader.NumberOfSections; Section++) {
        uint32_t VA = PE->SectionHeaders[Section].VirtualAddress;
        uint32_t Size = PE->SectionHeaders[Section].SizeOfRawData;

        if (VA <= RVA && RVA < VA + Size) {
            return Section;
        }
    }
    return -1;
}

// Get the file offset for a given relative virtual address
uint32_t PEGetOffsetForRVA(portable_executable* PE, uint32_t RVA) {
    int Section = PEGetEnclosingSection(PE, RVA);

    uint32_t SectionVA = PE->SectionHeaders[Section].VirtualAddress;
    uint32_t SectionOffset = PE->SectionHeaders[Section].PointerToRawData;

    return SectionOffset + RVA - SectionVA;
}

std::vector<std::wstring> PEGetImportDlls(portable_executable* PE) {
    std::vector<std::wstring> ImportDlls;

    uint32_t ImportTableRVA;
    if (PE->OptionalHeader.Magic == 0x10b) {
        ImportTableRVA = PE->OptionalHeader.Directories[DataDirectoryImport].VirtualAddress;
    } else {
        ImportTableRVA = PE->OptionalHeaderPlus.Directories[DataDirectoryImport].VirtualAddress;
    }
    if (ImportTableRVA == 0) {
        // No dependents
        return ImportDlls;
    }

    int ImportTableOffset = PEGetOffsetForRVA(PE, ImportTableRVA);

    uint8_t* ImportTableP = PE->ImageData + ImportTableOffset;
    while (1) {
        import_directory_entry Entry = {};
        memcpy(&Entry, ImportTableP, sizeof(import_directory_entry));

        if (Entry.ImportLookupTableRVA == 0) {
            break;
        }

        // Lookup name
        int NameOffset = PEGetOffsetForRVA(PE, Entry.NameRVA);
        std::string importDllName = (const char*)(PE->ImageData + NameOffset);

        // Convert dll to Unicode
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        ImportDlls.push_back(converter.from_bytes(importDllName));

        ImportTableP += sizeof(import_directory_entry);
    }
    return ImportDlls;
}

std::vector<std::wstring> StringSplit(const wchar_t* Str, wchar_t Sep) {
    std::vector<std::wstring> Splits;

    const wchar_t* Start = Str;
    while (*Str != 0) {
        if (*Str == Sep) {
            std::wstring Split(Start, Str);
            Splits.push_back(Split);
            Start = Str + 1;
        }

        Str++;
    }
    std::wstring Split(Start, Str);
    Splits.push_back(Split);

    return Splits;
}

// Entry of a referenced dll
struct dll_entry {
    // Name of this entry
    std::wstring Name = L"";

    // Path of the .dll or .exe referecing this dll (for local lookup)
    std::wstring RefererPath = L"";

    // Was this .dll found?
    bool WasFound = false;

    // The path where this dll was found
    std::wstring PathToDll = L"";

    uint32_t Architecture;
};

bool HasDllEntry(const std::vector<dll_entry>& DllEntries, std::wstring Name) {
    for (int I = 0; I < DllEntries.size(); I++) {
        // TODO: Case insensitive
        if (DllEntries[I].Name == Name) {
            return true;
        }
    }
    return false;
}

bool StringStartsWith(const std::wstring& Str, const std::wstring& With) {
    if (Str.size() < With.size())
        return false;

    for (int I = 0; I < With.size(); I++) {
        if (Str[I] != With[I]) {
            return false;
        }
    }
    return true;
}

std::wstring GetPathToFile(std::wstring FilePath) {
    int I;
    for (I = FilePath.size() - 1; I > 0; I--) {
        if (FilePath[I] == L'/' || FilePath[I] == L'\\') {
            break;
        }
    }
    if (I == 0) {
        return L".";
    }

    return FilePath.substr(0, I);
}

void PrintWithColor(int ColorAttribute, const wchar_t* Format, ...) {
    HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO Info;
    GetConsoleScreenBufferInfo(Console, &Info);

    int OriginalColor = Info.wAttributes;

    SetConsoleTextAttribute(Console, ColorAttribute);

    va_list Args;
    va_start(Args, Format);
    vwprintf(Format, Args);
    va_end(Args);


    SetConsoleTextAttribute(Console, OriginalColor);
}

std::wstring GetSystemDir() {
    wchar_t Path[MAX_PATH];
    GetSystemDirectoryW(Path, MAX_PATH);
    return Path;
}

std::wstring GetWindowsDir() {
    wchar_t Path[MAX_PATH];
    GetWindowsDirectoryW(Path, MAX_PATH);
    return Path;
}

std::wstring GetCurrentDir() {
    wchar_t Path[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, Path);
    return Path;
}

int wmain(int argc, wchar_t** argv) {
    // TODO: Handle api-ms-*.dll correctly
    // TODO: Ignore common windows dlls (ws2_32.dll, kernel32.dll, etc.)
    // TODO: Make more robust against invalid files (maybe use fuzzing)

    if (argc != 2) {
        printf("Please specify .exe/.dll to analyze.\n");
        return 1;
    }

    std::vector<std::wstring> Paths = StringSplit(_wgetenv(L"PATH"), ';');

    const wchar_t* ExePath = argv[1];
    std::wstring ExeDir  = GetPathToFile(ExePath);

    std::wstring SysDir     = GetSystemDir();
    std::wstring WinDir     = GetWindowsDir();
    std::wstring CurrentDir = GetCurrentDir();
    
    file_mapping ExeMapping = CreateReadOnlyFileMapping(ExePath);
    if (!ExeMapping.Data) {
        printf("Failed to open exe!\n");
        return 1;
    }

    std::vector<dll_entry> DllEntries;

    portable_executable PE = {};
    PEInit(&PE, ExeMapping.Data, ExeMapping.Size);
    std::vector<std::wstring> ImportDlls = PEGetImportDlls(&PE);
    CloseFileMapping(&ExeMapping);

    uint32_t MachineType = PE.CoffHeader.Machine;
    
    // Fill initial list of dll entries
    for (int I = 0; I < ImportDlls.size(); I++) {
        if (!StringStartsWith(ImportDlls[I], L"api-ms-")) {
            dll_entry DllEntry = {};
            DllEntry.Name = ImportDlls[I];
            DllEntry.RefererPath = ExeDir;
            DllEntries.push_back(DllEntry);
        }
    }

    // Process all dll entries until all are processed
    for (int I = 0; I < DllEntries.size(); I++) {
        dll_entry* Entry = &DllEntries[I];

        // Try to load the .dll on all paths until it is found
        file_mapping DllMapping = {};
        std::wstring Path = Entry->RefererPath + L"\\" + Entry->Name;
        DllMapping = CreateReadOnlyFileMapping(Path.c_str());

        // Load from System Directory
        if (!DllMapping.Data) {
            Path = SysDir + L"\\" + Entry->Name;
            DllMapping = CreateReadOnlyFileMapping(Path.c_str());
        }

        // Here comes the 16-bit system directory but this seems to be useless nowadays

        // Load from Windows Directory
        if (!DllMapping.Data) {
            Path = WinDir + L"\\" + Entry->Name;
            DllMapping = CreateReadOnlyFileMapping(Path.c_str());
        }

        // Search on current dir
        if (!DllMapping.Data) {
            Path = CurrentDir + L"\\" + Entry->Name;
            DllMapping = CreateReadOnlyFileMapping(Path.c_str());
        }
        
        // Search on environment path
        if (!DllMapping.Data) {
            for (int P = 0; P < Paths.size(); P++) {
                Path = Paths[P] + L"\\" + Entry->Name;
                DllMapping = CreateReadOnlyFileMapping(Path.c_str());

                if (DllMapping.Data) {
                    break;
                }
            }
        }

        if (DllMapping.Data) {
            Entry->PathToDll = Path;
            Entry->WasFound = true;
        }

        if (Entry->WasFound) {
            portable_executable PE = {};
            PEInit(&PE, DllMapping.Data, DllMapping.Size);
            std::vector<std::wstring> ImportDlls = PEGetImportDlls(&PE);

            Entry->Architecture = PE.CoffHeader.Machine;

            for (int J = 0; J < ImportDlls.size(); J++) {
                if (!StringStartsWith(ImportDlls[J], L"api-ms-")) {
                    if (!HasDllEntry(DllEntries, ImportDlls[J])) {
                        dll_entry DllEntry = {};
                        DllEntry.Name = ImportDlls[J];
                        DllEntry.RefererPath = GetPathToFile(Entry->PathToDll);
                        DllEntries.push_back(DllEntry);
                    }
                }
            }

            CloseFileMapping(&DllMapping);
        }
    }

    // Display Results
    wprintf(L"Dlls of %s\n", ExePath);

    for (int I = 0; I < DllEntries.size(); I++) {
        dll_entry* Entry = &DllEntries[I];

        const char* status;
        if (Entry->WasFound) {
            if (Entry->Architecture != MachineType) {
                PrintWithColor(12, L"%-8s", L"arch");
            } else {
                PrintWithColor(10, L"%-8s", L"ok");
            }
        } else {
            PrintWithColor(12, L"%-8s", L"missing");
        }

        wprintf(L" %-40s %s\n", Entry->Name.c_str(), Entry->PathToDll.c_str());
    }

    return 0;
}
