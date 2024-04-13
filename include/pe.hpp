#ifndef __PE_H__
#define __PE_H__

#include <string>
#include <headers.hpp>

class PE {

public:
    DOS_HEADER  dos_header;
    PE_HEADER   pe_header;

    PE ( std::string pe_path );

};

#endif