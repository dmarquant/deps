// References
// - https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
// - https://docs.microsoft.com/en-us/windows/win32/debug/pe-formt
// 
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

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

std::vector<std::string> PEGetImportDlls(portable_executable* PE) {
    std::vector<std::string> ImportDlls;

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
        ImportDlls.push_back((const char*)(PE->ImageData + NameOffset));

        ImportTableP += sizeof(import_directory_entry);
    }
    return ImportDlls;
}

typedef struct {
    int Size;
    uint8_t* Data;
} buffer;

buffer ReadEntireFile(const char* Path) {
    buffer Buffer = {};
    
    FILE* File = fopen(Path, "rb");
    if (File)
    {
        fseek(File, 0, SEEK_END);
        int FileSize = ftell(File);
        fseek(File, 0, SEEK_SET);

        uint8_t* Data = (uint8_t*)malloc(FileSize);
        if (FileSize == fread(Data, 1, FileSize, File)) {
            Buffer.Data = Data;
            Buffer.Size = FileSize;
        }
        else {
            free(Data);
        }
    }
    return Buffer;
}

void FreeBuffer(buffer* Buffer) {
    free(Buffer->Data);
}

std::vector<std::string> StringSplit(const char* Str, char Sep) {
    std::vector<std::string> Splits;

    const char* Start = Str;
    while (*Str != 0) {
        if (*Str == Sep) {
            std::string Split(Start, Str);
            Splits.push_back(Split);
            Start = Str + 1;
        }

        Str++;
    }
    std::string Split(Start, Str);
    Splits.push_back(Split);

    return Splits;
}

// Entry of a referenced dll
struct dll_entry {
    // Name of this entry
    std::string Name = "";

    // Path of the .dll or .exe referecing this dll (for local lookup)
    std::string RefererPath = "";

    // Was this .dll found?
    bool WasFound = false;

    // The path where this dll was found
    std::string PathToDll = "";

    uint32_t Architecture;
};

bool HasDllEntry(const std::vector<dll_entry>& DllEntries, std::string Name) {
    for (int I = 0; I < DllEntries.size(); I++) {
        // TODO: Case insensitive
        if (DllEntries[I].Name == Name) {
            return true;
        }
    }
    return false;
}

bool StringStartsWith(const std::string& Str, const std::string& With) {
    if (Str.size() < With.size())
        return false;

    for (int I = 0; I < With.size(); I++) {
        if (Str[I] != With[I]) {
            return false;
        }
    }
    return true;
}

std::string GetPathToFile(std::string FilePath) {
    int I;
    for (I = FilePath.size() - 1; I > 0; I--) {
        if (FilePath[I] == '/' || FilePath[I] == '\\') {
            break;
        }
    }
    if (I == 0) {
        return ".";
    }

    return FilePath.substr(0, I);
}

void PrintWithColor(int ColorAttribute, const char* Format, ...) {
    HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO Info;
    GetConsoleScreenBufferInfo(Console, &Info);

    int OriginalColor = Info.wAttributes;

    SetConsoleTextAttribute(Console, ColorAttribute);

    va_list Args;
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);


    SetConsoleTextAttribute(Console, OriginalColor);
}

std::string GetSystemDir() {
    char Path[MAX_PATH];
    GetSystemDirectoryA(Path, MAX_PATH);
    return Path;
}

std::string GetWindowsDir() {
    char Path[MAX_PATH];
    GetWindowsDirectoryA(Path, MAX_PATH);
    return Path;
}

std::string GetCurrentDir() {
    char Path[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, Path);
    return Path;
}

int main(int argc, char** argv) {
    // TODO: Use Unicode (wstrings)
    // TODO: Do memory mapping of the .dlls instead
    // TODO: Handle api-ms-*.dll correctly
    // TODO: Ignore common windows dlls (ws2_32.dll, kernel32.dll, etc.)

    if (argc != 2) {
        printf("Please specify .exe/.dll to analyze.\n");
        return 1;
    }

    std::vector<std::string> Paths = StringSplit(getenv("PATH"), ';');

    const char* ExePath = argv[1];
    std::string ExeDir  = GetPathToFile(ExePath);

    std::string SysDir = GetSystemDir();
    std::string WinDir = GetWindowsDir();
    std::string CurrentDir = GetCurrentDir();
    
    buffer ExeData = ReadEntireFile(ExePath);
    if (!ExeData.Data) {
        printf("Failed to read exe!\n");
        return 1;
    }

    std::vector<dll_entry> DllEntries;

    portable_executable PE = {};
    PEInit(&PE, ExeData.Data, ExeData.Size);
    std::vector<std::string> ImportDlls = PEGetImportDlls(&PE);
    FreeBuffer(&ExeData);

    uint32_t MachineType = PE.CoffHeader.Machine;
    
    // Fill initial list of dll entries
    for (int I = 0; I < ImportDlls.size(); I++) {
        if (!StringStartsWith(ImportDlls[I], "api-ms-")) {
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
        buffer DllData = {};
        std::string Path = Entry->RefererPath + "\\" + Entry->Name;
        DllData = ReadEntireFile(Path.c_str());

        // Load from System Directory
        if (!DllData.Data) {
            Path = SysDir + "\\" + Entry->Name;
            printf("Checking: %s\n", Path.c_str());
            DllData = ReadEntireFile(Path.c_str());
        }

        // Here comes the 16-bit system directory but this seems to be useless nowadays

        // Load from Windows Directory
        if (!DllData.Data) {
            Path = WinDir + "\\" + Entry->Name;
            DllData = ReadEntireFile(Path.c_str());
        }

        // Search on current dir
        if (!DllData.Data) {
            Path = CurrentDir + "\\" + Entry->Name;
            DllData = ReadEntireFile(Path.c_str());
        }
        
        // Search on environment path
        if (!DllData.Data) {
            for (int P = 0; P < Paths.size(); P++) {
                Path = Paths[P] + "\\" + Entry->Name;
                DllData = ReadEntireFile(Path.c_str());

                if (DllData.Data) {
                    break;
                }
            }
        }

        if (DllData.Data) {
            Entry->PathToDll = Path;
            Entry->WasFound = true;
        }

        if (Entry->WasFound) {
            portable_executable PE = {};
            PEInit(&PE, DllData.Data, DllData.Size);
            std::vector<std::string> ImportDlls = PEGetImportDlls(&PE);

            Entry->Architecture = PE.CoffHeader.Machine;

            for (int J = 0; J < ImportDlls.size(); J++) {
                if (!StringStartsWith(ImportDlls[J], "api-ms-")) {
                    if (!HasDllEntry(DllEntries, ImportDlls[J])) {
                        dll_entry DllEntry = {};
                        DllEntry.Name = ImportDlls[J];
                        DllEntry.RefererPath = GetPathToFile(Entry->PathToDll);
                        DllEntries.push_back(DllEntry);
                    }
                }
            }

            FreeBuffer(&DllData);
        }
    }

    // Display Results
    printf("Dlls of %s\n", ExePath);

    for (int I = 0; I < DllEntries.size(); I++) {
        dll_entry* Entry = &DllEntries[I];

        const char* status;
        if (Entry->WasFound) {
            if (Entry->Architecture != MachineType) {
                PrintWithColor(12, "%-8s", "arch");
            } else {
                PrintWithColor(10, "%-8s", "ok");
            }
        } else {
            PrintWithColor(12, "%-8s", "missing");
        }

        printf(" %-40s %s\n", Entry->Name.c_str(), Entry->PathToDll.c_str());
    }

    return 0;
}
