#include "lock_core.h"

#define BLOCK_SIZE 1<<6

u8 data[BLOCK_SIZE];

#define rdpmc(counter,low,high) \
	     __asm__ __volatile__("rdpmc" \
	        : "=a" (low), "=d" (high) \
	        : "c" (counter))

int main(int argc, char** argv) {

	int eax, ecx, edx;

	//Load data to cache
	for(int i=0;i<BLOCK_SIZE;i++)
		data[i] = data[i];

	// Read PMC
	rdpmc(ecx,eax,edx);

	lock_core();


	
	// Read PMC
	rdpmc(ecx,eax,edx);

	unlock_core();			


	return 0;
}
