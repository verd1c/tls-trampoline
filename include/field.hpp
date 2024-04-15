#ifndef __FIELD_H__
#define __FIELD_H__

#include <types.hpp>

template <class T> class Field {
    u32 size;
    T value;

    u64 offset;
};

#endif