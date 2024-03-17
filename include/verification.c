#include "verification.h"

u4 bigEndian_bytes_to_Integer( u1 *buffer, u4 size )
{
    u1 M = size;
    u4 result = 0;
    u1 *dataPtr = buffer;

    while( 0 < M )                                              /*loop integer bytes*/
    {
        result |= *(dataPtr++)<<( 8*(M-1) );
        M--;
    }

    return result;
}