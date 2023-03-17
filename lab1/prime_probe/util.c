
/**
 * 
 * CMU 15-799 Security for Software and Hardware Systems Spring 2023
 * 
 *  util.c is the implementaion of utility functions to measure time, flush a line, and shuffle.
 * 
 */

#include "util.h"

/* Measure access time of addr. */
CYCLES measure_line_access_time(ADDR_PTR addr)
{
	CYCLES cycles;

	asm volatile("mov %1, %%r8\n\t"
	"lfence\n\t"
	"rdtsc\n\t"
	"mov %%eax, %%edi\n\t"
	"mov (%%r8), %%r8\n\t"
	"lfence\n\t"
	"rdtsc\n\t"
	"sub %%edi, %%eax\n\t"
	: "=a"(cycles) /*output*/
	: "r"(addr)
	: "r8", "edi");	

	return cycles;
}

/*
 * clfush addr.
 */
void clflush(ADDR_PTR addr)
{
    asm volatile ("clflush (%0)"::"r"(addr));
}


/*
* Shuffle n elements of array
* From https://benpfaff.org/writings/clc/shuffle.html
*/
void shuffle(char **array, size_t n) {
    if (n > 1) {
        for (size_t i = 0; i < n - 1; i++) {
            size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
            char *t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}