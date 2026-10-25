#include <stdio.h>
#include <string.h>
#include "pe_parser.h"

void parse_pe(const char* filepath) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", filepath);
        return;
    }

    IMAGE_DOS_HEADER dos_header;
    if (fread(&dos_header, sizeof(dos_header), 1, fp) != 1) {
        fprintf(stderr, "Failed to read DOS header\n");
        fclose(fp);
        return;
    }

    if (dos_header.e_magic != 0x5A4D) { // 'MZ' in little-endian
        fprintf(stderr, "Invalid MZ signature\n");
        fclose(fp);
        return;
    }

    fseek(fp, dos_header.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt_headers;
    if (fread(&nt_headers, sizeof(nt_headers), 1, fp) != 1) {
        fprintf(stderr, "Failed to read NT headers\n");
        fclose(fp);
        return;
    }

    if (nt_headers.Signature != 0x00004550) { // "PE\0\0" in little-endian
        fprintf(stderr, "Invalid PE signature\n");
        fclose(fp);
        return;
    }

    const char* machine_str = "Unknown";
    switch (nt_headers.FileHeader.Machine) {
        case 0x014C: machine_str = "i386 (x86)"; break;
        case 0x8664: machine_str = "AMD64 (x64)"; break;
    }

    printf("PE File Information:\n");
    printf("  Machine: %s\n", machine_str);
    printf("  NumberOfSections: %d\n", nt_headers.FileHeader.NumberOfSections);
    printf("  SizeOfImage: %u bytes\n", nt_headers.OptionalHeader.SizeOfImage);
    printf("  AddressOfEntryPoint: 0x%X\n", nt_headers.OptionalHeader.AddressOfEntryPoint);

    fclose(fp);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_pe>\n", argv[0]);
        return 1;
    }
    parse_pe(argv[1]);
    return 0;
}
