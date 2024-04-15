#include <headers.hpp>
#include <utils.hpp>
#include <math.h>

std::string data_directory_names[] = {
    "ExportTable",
    "ImportTable",
    "ResourceTable",
    "ExceptionTable",
    "CertificateTable",
    "BaseRelocationTable",
    "Debug",
    "ArchitectureData",
    "GlobalPtr",
    "TLSTable",
    "LoadConfigTable",
    "BoundImport",
    "ImportAddressTable",
    "DelayImportDescriptor",
    "CLRRuntimeHeader",
    "NULL"
};

DOS_HEADER::DOS_HEADER( std::vector<u8> pe_data ) {
    u8 *raw_data = pe_data.data();
    u16 ctr = 0;

    e_magic = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_cblp = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_cp = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_crlc = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_cparhdr = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_minalloc = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_maxalloc = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_ss = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_sp = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_csum = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_ip = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_cs = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_lfarlc = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_ovno = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res[0] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res[1] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res[2] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res[3] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_oemid = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_oeminfo = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[0] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[1] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[2] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[3] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[4] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[5] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[6] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[7] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[8] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_res2[9] = Utils::read_u16( raw_data + sizeof(u16) * (ctr++) );
    e_lfanew = Utils::read_u32( raw_data + sizeof(u16) * (ctr++) );
}

PE_HEADER::PE_HEADER( std::vector<u8> pe_data, i32 offset_nt_header )
    :   coff_header( pe_data, offset_nt_header ),
        optional_header( pe_data, offset_nt_header ) {

    this->initialize_sections( pe_data );
}

void PE_HEADER::initialize_sections( std::vector<u8> pe_data ) {
    u16 num_of_sections = this->coff_header.num_of_sections;
    u8 *raw_data = pe_data.data() + this->optional_header.sections_offset;
    u32 data_ptr = 0;

    for (u16 idx = 0; idx < num_of_sections; ++idx) {
        std::string name( (const char *)raw_data + data_ptr );
        data_ptr += 8;

        u32 virtual_size = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u32 virtual_address = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u32 raw_size = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u32 raw_address = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u32 reloc_address = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u32 linenumbers = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        u16 relocations_number = Utils::read_u16( raw_data + data_ptr );
        data_ptr += 2;

        u16 linenumbers_number = Utils::read_u16( raw_data + data_ptr );
        data_ptr += 2;

        u32 characteristics = Utils::read_u32( raw_data + data_ptr );
        data_ptr += 4;

        sections.push_back(SectionHeader(
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_address,
            reloc_address,
            linenumbers,
            relocations_number,
            linenumbers_number,
            characteristics
        ));
    }
}

COFF_HEADER::COFF_HEADER( std::vector<u8> pe_data, i32 offset_nt_header ) {
    u8 *raw_data = pe_data.data() + offset_nt_header;
    u32 data_ptr = 0;

    signature = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    machine = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    num_of_sections = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    time_date_stamp = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    pointer_to_symbol_table = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    number_of_symbol_table = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    size_of_optional_header = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    characteristics = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;
}

OptionalHeader::OptionalHeader( std::vector<u8> pe_data, i32 offset_nt_header ) {
    u8 *raw_data = pe_data.data();
    u32 data_ptr = offset_nt_header + 0x18;

    // printf("data ptr: %x\n", data_ptr);
    magic = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    major_linker_version = Utils::read_u8( raw_data + data_ptr );
    data_ptr += 1;

    minor_linker_version = Utils::read_u8( raw_data + data_ptr );
    data_ptr += 1;

    size_of_code = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    size_of_initialized_data = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    size_of_uninitialized_data = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    address_of_entry_point = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    base_of_code = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    // printf("data ptr: %x\n", data_ptr);
    // base_of_data = Utils::read_u32( raw_data + data_ptr );
    // data_ptr += 4;

    // printf("data ptr: %x\n", data_ptr);
    image_base = Utils::read_u64( raw_data + data_ptr );
    data_ptr += 8;

    section_alignment = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    file_alignment = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    major_operating_system_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    minor_operating_system_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    major_image_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    minor_image_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    major_subsystem_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    minor_subsystem_version = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    win32_versio_value = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    size_of_image = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    size_of_headers = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    checksum = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    subsystem = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    dll_characteristics = Utils::read_u16( raw_data + data_ptr );
    data_ptr += 2;

    size_of_stack_reserve = Utils::read_u64( raw_data + data_ptr );
    data_ptr += 8;

    size_of_stack_commit = Utils::read_u64( raw_data + data_ptr );
    data_ptr += 8;

    size_of_heap_reserve = Utils::read_u64( raw_data + data_ptr );
    data_ptr += 8;

    size_of_heap_commit = Utils::read_u64( raw_data + data_ptr );
    data_ptr += 8;

    loader_flags = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    number_of_rva_and_sizes = Utils::read_u32( raw_data + data_ptr );
    data_ptr += 4;

    for (u32 idx = 0; idx < number_of_rva_and_sizes; ++idx) {
        directories.push_back(new DataDirectory(
            data_directory_names[idx],
            Utils::read_u32( raw_data + data_ptr ),
            Utils::read_u32( raw_data + data_ptr + 4)
        ));

        data_ptr += 8;
    }

    this->sections_offset = data_ptr;
}

DataDirectory::DataDirectory( std::string name, u32 base, u32 size ) {
    this->name = name;
    this->base = base;
    this->size = size;
}

SectionHeader::SectionHeader(
    std::string name,
    u32 virtual_size,
    u32 virtual_address,
    u32 size_of_raw_data,
    u32 pointer_to_raw_data,
    u32 pointer_to_relocations,
    u32 pointer_to_linenumbers,
    u16 number_of_relocations,
    u16 number_of_linenumbers,
    u32 characteristics
): name{ name }, virtual_size{ virtual_size }, virtual_address{ virtual_address },
size_of_raw_data{ size_of_raw_data }, pointer_to_raw_data{ pointer_to_raw_data }, 
pointer_to_relocations{ pointer_to_relocations }, pointer_to_linenumbers{ pointer_to_linenumbers },
number_of_relocations{ number_of_relocations }, number_of_linenumbers{ number_of_linenumbers },
characteristics{ characteristics } {

}


// default
DOS_HEADER::DOS_HEADER( ) { }
PE_HEADER::PE_HEADER( ) { }
COFF_HEADER::COFF_HEADER( ) { }
OptionalHeader::OptionalHeader( ) { }
DataDirectory::DataDirectory( ) { }
SectionHeader::SectionHeader( ) { }