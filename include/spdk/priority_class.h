#ifndef SPDK_PRIORITY_CLASS_H
#define SPDK_PRIORITY_CLASS_H


#define NBITS_PRIORITY_CLASS 3
#define NBITS_GEOMETRY      5
#define NBITS_USED          8

/* shift priority class value left by this to get the OR-mask or shift right by this after applying the priority 
class mask PRIORITY_CLASS_MASK to get the priority class as an integer
*/
#define PRIORITY_CLASS_BITS_POS (64 - NBITS_PRIORITY_CLASS)

#define GEOMETRY_BITS_POS   (PRIORITY_CLASS_BITS_POS - NBITS_GEOMETRY) // = 57
#define GEOMETRY_MASK       (((1ULL << NBITS_GEOMETRY) - 1) << GEOMETRY_BITS_POS)

#define PRIORITY_CLASS_MASK (0xFFFFFFFFFFFFFFFF << PRIORITY_CLASS_BITS_POS)
#define MASK_OUT_USED_BITS (0xFFFFFFFFFFFFFFFF >> NBITS_USED)
#define MIN_PRIORITY_CLASS 0
// #define MAX_PRIORITY_CLASS ((1 << NBITS_PRIORITY_CLASS) - 1)
#define MAX_PRIORITY_CLASS 7
#define PREMIUM_PRIORITY_CLASS  1

#endif