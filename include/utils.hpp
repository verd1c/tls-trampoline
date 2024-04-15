#ifndef __UTILS_H__
#define __UTILS_H__

#include <types.hpp>
#include <fstream>

namespace Utils {

u64 read_u64(u8 *data);
u32 read_u32(u8 *data);
u16 read_u16(u8 *data);
u8 read_u8(u8 *data);

template<typename T>
void write_num( std::ofstream& o, T num ) {
    o.write( (char *)&num, sizeof(num) );
}

}

#endif