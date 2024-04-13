#include <iostream>
#include <fstream>
#include <pe.hpp>

PE::PE ( std::string pe_path ) {
    std::basic_ifstream<u8> pe_file ( pe_path, std::ios::binary );

    std::vector<u8> pe_data ( ( std::istreambuf_iterator<u8> (pe_file) ), std::istreambuf_iterator<u8> ( ) );

    dos_header = DOS_HEADER( pe_data );
    pe_header = PE_HEADER( pe_data, dos_header.e_lfanew );

}