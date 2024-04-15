#ifndef __PE_H__
#define __PE_H__

#include <string>
#include <headers.hpp>
#include <vector>
#include <utils.hpp>
#include <section.hpp>

class PE {

public:
    DOS_HEADER  dos_header;
    std::vector<u8> dos_stub;
    PE_HEADER   pe_header;
    std::vector<Section> sections;

    PE ( std::string pe_path );

    void save( std::string pe_path );

};

#endif