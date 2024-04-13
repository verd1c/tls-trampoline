#include <utils.hpp>

u32 Utils::read_u32(u8 *data) {
    return *reinterpret_cast<u32 *>( data );
}

u16 Utils::read_u16(u8 *data) {
    return *reinterpret_cast<u16 *>( data );
}

u8 Utils::read_u8(u8 *data) {
    return *reinterpret_cast<u8 *>( data );
}