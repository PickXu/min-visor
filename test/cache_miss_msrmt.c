#include "lock_core.h"
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#define BLOCK_SIZE 1<<21
#define ITERATIONS BLOCK_SIZE>>2
#define NUM_THREDS 1<<0

#define MEM_ 0x01D3
#define LAT_MISS 0x412e		//LONGEST_LAT_CACHE.MISS
#define L3_MISS	0x10cb		//MEM_LOAD_RETIRED.L3_MISS
#define UNC_L3_MISS 0x0309	//UNC_L3_MISS.ANY

#define ITLB_MISS 	0x0185	//ITLB_MISSES.MISS_CAUSES_A_WALK
#define DTLB_MISS 	0x0149	//DTLB_MISSES.ANY
#define L2_MISS 	0xaa24	//L2_RQSTS.MISS
#define DTLB_LOAD_MISS	0x8108	//DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK
#define MEM_DTLB_MISS	0x80cb	//MEM_LOAD_RETIRED.DTLB_MISS

uint32_t data[BLOCK_SIZE];

uint16_t events[] = {0x0203,0x0803,0x0105,0x0205,0x0107,0x8108,0x8208,};

int main(int argc, char** argv) {

	int eax, ebx, ecx, edx,eax1,eax2,eax3,eax4,eax5,eax6,edx1,edx2,edx3,edx4,edx5,edx6;
	int ret,i,j;
        pid_t pid;
	pid_t children[NUM_THREDS];
	uint64_t start, end;
	unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;

#ifdef __NON_PREEMPT__
	printf("Non-preemptable mode.\n");
#else
	printf("Conventional mode.\n");
#endif
        // Start NUM_THREDS competing processes
	for(i=0;i<NUM_THREDS;i++)
	{
		pid = fork();
		if (pid!=0) children[i] = pid; 	
		else break;
	}

	if (pid == 0) {
		while(1) ;
	} else {
	for(i=0;i<NUM_THREDS;i++)
		printf("Forked Process: %d\n", children[i]);
	printf("Entering testing section...\n");


	// Init IA32_PERFEVTSELx to count specific events 
	eax = 26;
	ebx = 0;	//IA32_PERFEVTSEL(0+ebx);IA32_PMC(0+ebx)
	ecx = DTLB_MISS;
	asm volatile ("vmcall\n"
			:
			: "a" (eax), "b" (ebx), "c" (ecx)
			);
	
	ebx = 1;	//IA32_PERFEVTSEL(0+ebx);IA32_PMC(0+ebx)
	ecx = LLC_MISS;
	asm volatile ("vmcall\n"
			:
			: "a" (eax), "b" (ebx), "c" (ecx)
			);
	ebx = 2;
	ecx = ITLB_MISS;
	asm volatile ("vmcall\n"
			:
			: "a" (eax), "b" (ebx), "c" (ecx)
			);


#ifdef __USER_APP__
	asm volatile(
		     "rdtsc\n"
		     "mov %%edx,%0\n"
		     "mov %%eax,%1\n"
		     : "=r" (cycles_high), "=r"(cycles_low)
		     : : "%rax", "%rbx", "%rcx", "%rdx");
	asm volatile(
		     "rdtsc\n"
		     "mov %%edx,%0\n"
		     "mov %%eax,%1\n"
		     : "=r" (cycles_high1), "=r"(cycles_low1)
		     : : "%rax", "%rbx", "%rcx", "%rdx");

        asm volatile("rdpmc\n"
			: "=a" (eax1), "=d" (edx1)
			: "c" (0)
			);
	asm volatile("rdpmc\n"
			: "=a" (eax2), "=d" (edx2)
			: "c" (1)
			);
	asm volatile("rdpmc\n"
			: "=a" (eax5), "=d" (edx5)
			: "c" (2)
			);

	asm volatile("rdpmc\n"
			: "=a" (eax3), "=d" (edx3)
			: "c" (0)
			);
	asm volatile("rdpmc\n"
			: "=a" (eax4), "=d" (edx4)
			: "c" (1)
			);
	asm volatile("rdpmc\n"
			: "=a" (eax6), "=d" (edx6)
			: "c" (2)
			);

	//Load data to cache
	for(i=0;i<BLOCK_SIZE;i++)
		data[i] = i;



#ifdef __NON_PREEMPT__
	assert((ret=lock_core()) == 0);
#endif

	for(j=0;j<ITERATIONS;j++) {
	// Read IA32_PMCx 
        asm volatile("rdpmc\n"
			: "=a" (eax1), "=d" (edx1)
			: "c" (0)
			);
	 asm volatile("rdpmc\n"
			: "=a" (eax2), "=d" (edx2)
			: "c" (1)
			);
	 asm volatile("rdpmc\n"
			: "=a" (eax5), "=d" (edx5)
			: "c" (2)
			);

	
	asm volatile("": : :"memory");
	asm volatile(
		     "rdtsc\n"
		     "mov %%edx,%0\n"
		     "mov %%eax,%1\n"
		     : "=r" (cycles_high), "=r"(cycles_low)
		     : : "%rax", "%rbx", "%rcx", "%rdx");

	
	asm volatile("Loop:\n");

	for(i=0;i<BLOCK_SIZE;i++)
		data[i] = data[i];

	asm volatile("": : :"memory");
	asm volatile(
		     "rdtsc\n"
		     "mov %%edx,%0\n"
		     "mov %%eax,%1\n"
		     : "=r" (cycles_high1), "=r"(cycles_low1)
		     : : "%rax", "%rbx", "%rcx", "%rdx");

	// Read IA32_PMCx
        asm volatile("rdpmc\n"
			: "=a" (eax3), "=d" (edx3)
			: "c" (0)
			);
	asm volatile("rdpmc\n"
			: "=a" (eax4), "=d" (edx4)
			: "c" (1)
			);
	 asm volatile("rdpmc\n"
			: "=a" (eax6), "=d" (edx6)
			: "c" (2)
			);

	start = (((uint64_t) cycles_high << 32)|cycles_low);
	end = (((uint64_t) cycles_high1 << 32)|cycles_low1);

	data[j*4] = (eax3-eax1);
	data[j*4+1] = (eax4-eax2);
	data[j*4+2] = (end-start)>>32;
	data[j*4+3] = ((end-start)&0xffffffff);
	}


#ifdef __NON_PREEMPT__
	assert((ret=unlock_core()) == 0);			
#endif
	for(j=0;j<ITERATIONS;j+=4)
		printf("DTLB_MISS: %d, LLC_MISS: %d, Time: %u\n",data[j*4],data[j*4+1],data[j*4+3]);
#else
	//Delegate the test to hypervisor
	eax = 28;
	ebx = BLOCK_SIZE;
	ecx = ITERATIONS;
	asm volatile("vmcall\n"
			: : "a" (eax), "b" (ebx), "c" (ecx));
#endif

	// Kill Children
	for (i=0;i<NUM_THREDS;i++)
		kill(children[i],SIGKILL);
	}

	return 0;
}
