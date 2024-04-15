#include <utils.hpp>

u64 Utils::read_u64(u8 *data) {
    return *reinterpret_cast<u64 *>( data );
}

u32 Utils::read_u32(u8 *data) {
    return *reinterpret_cast<u32 *>( data );
}

u16 Utils::read_u16(u8 *data) {
    return *reinterpret_cast<u16 *>( data );
}

u8 Utils::read_u8(u8 *data) {
    return *reinterpret_cast<u8 *>( data );
}