#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <types.hpp>
#include <string>
#include <vector>
#include <stdint.h>

class PE;

class DOS_HEADER {

public:
    u16   e_magic;                     // Magic number
    u16   e_cblp;                      // Bytes on last page of file
    u16   e_cp;                        // Pages in file
    u16   e_crlc;                      // Relocations
    u16   e_cparhdr;                   // Size of header in paragraphs
    u16   e_minalloc;                  // Minimum extra paragraphs needed
    u16   e_maxalloc;                  // Maximum extra paragraphs needed
    u16   e_ss;                        // Initial (relative) SS value
    u16   e_sp;                        // Initial SP value
    u16   e_csum;                      // Checksum
    u16   e_ip;                        // Initial IP value
    u16   e_cs;                        // Initial (relative) CS value
    u16   e_lfarlc;                    // File address of relocation table
    u16   e_ovno;                      // Overlay number
    u16   e_res[4];                    // Reserved words
    u16   e_oemid;                     // OEM identifier (for e_oeminfo)
    u16   e_oeminfo;                   // OEM information; e_oemid specific
    u16   e_res2[10];                  // Reserved words
    i32   e_lfanew;                    // Offset to the NT header

    size_t size;

    DOS_HEADER( );
    DOS_HEADER( std::vector<u8> );
};

class COFF_HEADER {

public:
    u32 signature;
    u16 machine;
    u16 num_of_sections;
    u32 time_date_stamp;
    u32 pointer_to_symbol_table;    // depracated
    u32 number_of_symbol_table;
    u16 size_of_optional_header;
    u16 characteristics;

    COFF_HEADER( );
    COFF_HEADER( std::vector<u8>, i32 );
};

class OptionalHeader { 
public:
    u16 magic;
    u8  major_linker_version;
    u8  minor_linker_version;
    u32 size_of_code;
    u32 size_of_initialized_data;
    u32 size_of_uninitialized_data;
    u32 address_of_entry_point;         // RVA
    u32 base_of_code;                   // RVA
    u32 base_of_data;                   // RVA

    u32 image_base;
    u32 section_alignment;
    u32 file_alignment;
    u16 major_operating_system_version;
    u16 minor_operating_system_version;
    u16 major_image_version;
    u16 minor_image_version;
    u16 major_subsystem_version;
    u16 minor_subsystem_version;
    u32 win32_versio_value;
    u32 size_of_image;
    u32 size_of_headers;
    u32 checksum;
    u16 subsystem;
    u16 dll_characteristics;
    u32 size_of_stack_reserve;
    u32 size_of_stack_commit;
    u32 size_of_heap_reserve;
    u32 size_of_heap_commit;
    u32 loader_flags;
    u32 number_of_rva_and_sizes;

    OptionalHeader( );
    OptionalHeader( std::vector<u8>, i32 );
};

class PE_HEADER {
public: 
    COFF_HEADER coff_header;
    OptionalHeader optional_header;

    size_t size;

    PE_HEADER( );
    PE_HEADER( std::vector<u8>, i32 );

};


#endif