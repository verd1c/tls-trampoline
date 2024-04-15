#include <iostream>
#include <fstream>
#include <pe.hpp>
#include <utils.hpp>
#include <vector>

PE::PE ( std::string pe_path ) {
    std::ifstream pe_file ( pe_path, std::ios::binary );

    std::vector<u8> pe_data(std::istreambuf_iterator<char>(pe_file), {});

    dos_header = DOS_HEADER( pe_data );
    dos_stub = std::vector<u8>( pe_data.begin() + 0x40, pe_data.begin() + dos_header.e_lfanew );
    pe_header = PE_HEADER( pe_data, dos_header.e_lfanew );

    for (SectionHeader sh : pe_header.sections) {
        u32 raw_start = sh.pointer_to_raw_data;
        u32 raw_end = sh.pointer_to_raw_data + sh.size_of_raw_data;
        Section s;
        s.data = std::vector<u8>( pe_data.begin() + raw_start, pe_data.begin() + raw_end );
        sections.push_back( s );
    }
}

// generate the PE file
void PE::save( std::string pe_path ) {
    std::ofstream pe_file ( pe_path, std::ios::out | std::ios::binary );

    // DOS HEADER
    DOS_HEADER dosh = dos_header;
    Utils::write_num( pe_file, dosh.e_magic );
    Utils::write_num( pe_file, dosh.e_cblp );
    Utils::write_num( pe_file, dosh.e_cp );
    Utils::write_num( pe_file, dosh.e_crlc );
    Utils::write_num( pe_file, dosh.e_cparhdr );
    Utils::write_num( pe_file, dosh.e_minalloc );
    Utils::write_num( pe_file, dosh.e_maxalloc );
    Utils::write_num( pe_file, dosh.e_ss );
    Utils::write_num( pe_file, dosh.e_sp );
    Utils::write_num( pe_file, dosh.e_csum );
    Utils::write_num( pe_file, dosh.e_ip );
    Utils::write_num( pe_file, dosh.e_cs );
    Utils::write_num( pe_file, dosh.e_lfarlc );
    Utils::write_num( pe_file, dosh.e_ovno );
    Utils::write_num( pe_file, dosh.e_res[0] );
    Utils::write_num( pe_file, dosh.e_res[1] );
    Utils::write_num( pe_file, dosh.e_res[2] );
    Utils::write_num( pe_file, dosh.e_res[3] );
    Utils::write_num( pe_file, dosh.e_oemid );
    Utils::write_num( pe_file, dosh.e_oeminfo );
    Utils::write_num( pe_file, dosh.e_res2[0] );
    Utils::write_num( pe_file, dosh.e_res2[1] );
    Utils::write_num( pe_file, dosh.e_res2[2] );
    Utils::write_num( pe_file, dosh.e_res2[3] );
    Utils::write_num( pe_file, dosh.e_res2[4] );
    Utils::write_num( pe_file, dosh.e_res2[5] );
    Utils::write_num( pe_file, dosh.e_res2[6] );
    Utils::write_num( pe_file, dosh.e_res2[7] );
    Utils::write_num( pe_file, dosh.e_res2[8] );
    Utils::write_num( pe_file, dosh.e_res2[9] );
    Utils::write_num( pe_file, dosh.e_lfanew );

    // DOS STUB
    pe_file.write( (const char *)dos_stub.data(), dos_stub.size() );

    // PE_HEADER
    PE_HEADER peh = pe_header;

    // COFF HEADER
    COFF_HEADER coffh = peh.coff_header;
    Utils::write_num( pe_file, coffh.signature );
    Utils::write_num( pe_file, coffh.machine );
    Utils::write_num( pe_file, coffh.num_of_sections );
    Utils::write_num( pe_file, coffh.time_date_stamp );
    Utils::write_num( pe_file, coffh.pointer_to_symbol_table );
    Utils::write_num( pe_file, coffh.number_of_symbol_table );
    Utils::write_num( pe_file, coffh.size_of_optional_header );
    Utils::write_num( pe_file, coffh.characteristics );

    // OptionalHeader
    OptionalHeader oh = peh.optional_header;
    Utils::write_num( pe_file, oh.magic );
    Utils::write_num( pe_file, oh.major_linker_version );
    Utils::write_num( pe_file, oh.minor_linker_version );
    Utils::write_num( pe_file, oh.size_of_code );
    Utils::write_num( pe_file, oh.size_of_initialized_data );
    Utils::write_num( pe_file, oh.size_of_uninitialized_data );
    Utils::write_num( pe_file, oh.address_of_entry_point );
    Utils::write_num( pe_file, oh.base_of_code );
    Utils::write_num( pe_file, oh.image_base );
    Utils::write_num( pe_file, oh.section_alignment );
    Utils::write_num( pe_file, oh.file_alignment );
    Utils::write_num( pe_file, oh.major_operating_system_version );
    Utils::write_num( pe_file, oh.minor_operating_system_version );
    Utils::write_num( pe_file, oh.major_image_version );
    Utils::write_num( pe_file, oh.minor_image_version );
    Utils::write_num( pe_file, oh.major_subsystem_version );
    Utils::write_num( pe_file, oh.minor_subsystem_version );
    Utils::write_num( pe_file, oh.win32_versio_value );
    Utils::write_num( pe_file, oh.size_of_image );
    Utils::write_num( pe_file, oh.size_of_headers );
    Utils::write_num( pe_file, oh.checksum );
    Utils::write_num( pe_file, oh.subsystem );
    Utils::write_num( pe_file, oh.dll_characteristics );
    Utils::write_num( pe_file, oh.size_of_stack_reserve );
    Utils::write_num( pe_file, oh.size_of_stack_commit );
    Utils::write_num( pe_file, oh.size_of_heap_reserve );
    Utils::write_num( pe_file, oh.size_of_heap_commit );
    Utils::write_num( pe_file, oh.loader_flags );
    Utils::write_num( pe_file, oh.number_of_rva_and_sizes );

    for (DataDirectory *dd : oh.directories) {
        Utils::write_num( pe_file, dd->base );
        Utils::write_num( pe_file, dd->size );
    }

    //
    for (SectionHeader sh : peh.sections) {
        char name[8] = { 0 };
        strcpy(name, sh.name.c_str());
        pe_file.write(name, 8);

        Utils::write_num( pe_file, sh.virtual_size );
        Utils::write_num( pe_file, sh.virtual_address );
        Utils::write_num( pe_file, sh.size_of_raw_data );
        Utils::write_num( pe_file, sh.pointer_to_raw_data );
        Utils::write_num( pe_file, sh.pointer_to_relocations );
        Utils::write_num( pe_file, sh.pointer_to_linenumbers );
        Utils::write_num( pe_file, sh.number_of_relocations );
        Utils::write_num( pe_file, sh.number_of_linenumbers );
        Utils::write_num( pe_file, sh.characteristics );
    }


    SectionHeader first_section = peh.sections.front();
    u32 diff = first_section.pointer_to_raw_data - pe_file.tellp();
    for (int i = 0; i < diff; ++i) pe_file.write( "\x00", 1);

    for (Section s : sections) {
        pe_file.write( (const char *)s.data.data(), s.data.size() );
    }


}