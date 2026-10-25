#!/usr/bin/env python3
import struct

def write_pe(path, total_size=1024):
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'  # e_magic
    # e_lfanew at offset 60 (little-endian int32)
    e_lfanew = 64  # PE header starts right after DOS header
    struct.pack_into('<i', dos_header, 60, e_lfanew)

    # Data after DOS header: Pad to e_lfanew (64)
    padding = b'\x00' * (e_lfanew - 64)

    # NT Headers
    # Signature (4 bytes) - "PE\0\0"
    pe_sig = b'PE\x00\x00'

    # File Header (20 bytes)
    file_header = struct.pack('<HHIIIHH',
        0x8664,           # Machine (AMD64)
        1,                # NumberOfSections
        0,                # TimeDateStamp
        0,                # PointerToSymbolTable
        0,                # NumberOfSymbols
        0xE0,             # SizeOfOptionalHeader (224 bytes)
        0x22              # Characteristics
    )

    # Optional Header (PE32) - minimal required fields
    opt_header = bytearray(224)
    # Magic (0x10B for PE32)
    struct.pack_into('<H', opt_header, 0, 0x10B)
    # AddressOfEntryPoint
    struct.pack_into('<I', opt_header, 28, 0x1000)
    # SizeOfImage
    struct.pack_into('<I', opt_header, 96, 0x1000)

    # File alignment (file alignment must be at least 512)
    struct.pack_into('<I', opt_header, 36, 0x200)

    # Section header (1 个 4 字节对齐，最小 40 字节)
    section_header = bytearray(40)
    name = b'.text\0\0\0\0'
    section_header[0:8] = name
    struct.pack_into('<I', section_header, 8, 0x1000)  # VirtualSize
    struct.pack_into('<I', section_header, 12, 0x1000)  # VirtualAddress
    struct.pack_into('<I', section_header, 16, 0x200)   # SizeOfRawData
    struct.pack_into('<I', section_header, 20, 0x200)   # PointerToRawData
    struct.pack_into('<I', section_header, 32, 0x60000020)  # Characteristics

    # 填满整个文件至 total_size
    remaining = total_size - (e_lfanew + 4 + 20 + 224 + 40)
    footer = b'\x00' * remaining if remaining > 0 else b''

    # 组装所有部分
    content = dos_header + padding + pe_sig + file_header + opt_header + section_header + footer
    # 确保长度正好是 total_size
    content = content[:total_size]

    with open(path, 'wb') as f:
        f.write(content)

if __name__ == '__main__':
    write_pe('dummy_pe.exe', 1024)
    print('Created dummy_pe.exe (1KB)')
