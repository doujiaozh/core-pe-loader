#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdint.h>

#pragma pack(push, 1)

// Minimal DOS header with e_magic and e_lfanew at offset 60
typedef struct {
    uint16_t e_magic;
    char     _pad[58];
    int32_t  e_lfanew;
} IMAGE_DOS_HEADER;

// DATA_DIRECTORY entry
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

// File header
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

// Optional header (PE32)
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

// NT headers
typedef struct {
    uint32_t                         Signature;
    IMAGE_FILE_HEADER                FileHeader;
    IMAGE_OPTIONAL_HEADER32          OptionalHeader;
} IMAGE_NT_HEADERS;

#pragma pack(pop)

void parse_pe(const char *filepath);

#endif // PE_PARSER_H
