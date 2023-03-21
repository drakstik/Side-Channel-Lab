
/**
 * 
 * CMU 15-799 Security for Software and Hardware Systems Spring 2023
 * 
 *  util.h is a header file with utility functions to measure time, flush a line, and shuffle.
 * 
 */

#include <stdio.h>
#include <stdlib.h>

#include <inttypes.h>
#include <time.h>
#include <stdbool.h>

#ifndef UTIL_H_
#define UTIL_H_

#define ADDR_PTR uint64_t 
#define CYCLES uint32_t

CYCLES measure_line_access_time(ADDR_PTR addr);

void clflush(ADDR_PTR addr);

void shuffle(char **array, size_t n);

#endif
