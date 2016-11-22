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

uint16_t events[] = {0x0203,0x0803,0x0105,0x0205,0x0107,0x8108,0x8208,0x8408,0x8808,
		     0x010e,0x100e,0x200e,0x400e,0x0110,0x1010,0x2010,0x4010,0x8010,
		     0x0111,0x0211,0x0114,0x0124,0x0324,0x0424,0x0824,0x0c24,0x1024,
		     0x2024,0x3024,0x4024,0x8024,0xc024,0x0127,0x0827,0x0f27,0x0128,
		     0x0428,0x0828,0x0f28,0x4f2e,0x412e,0x003c,0x013c,0x0148,0x0149,
		     0x0249,0x0449,0x1049,0x014c,0x024c,0x0151,0x0458,0x0858,0x0158,
		     0x0258,0x015c,0x025c,0x015e,0x045f,0x0160,0x0260,0x0460,0x0860,
		     0x0163,0x0263,0x0279,0x0479,0x0879,0x1079,0x2079,0x3079,0x1879,
		     0x2479,0x3c79,0x0480,0x0280,0x0185,0x0285,0x0485,0x1085,0x0187,
		     0x0487,0x0188,0x0288,0x0488,0x0888,0x1088,0x2088,0x4088,0x8088,
		     0xff88,0x0189,0x0489,0x0889,0x1089,0x2089,0x4089,0x8089,0xff89,
		     0x019c,0x01a1,0x02a1,0x0ca1,0x30a1,0x40a1,0x80a1,0x01a2,0x04a2,
		     0x08a2,0x10a2,0x01a3,0x02a3,0x04a3,0x05a3,0x06a3,0x08a3,0x0ca3,
		     0x01a8,0x01ab,0x02ab,0x08ac,0x01ae,0x01b0,0x02b0,0x04b0,0x08b0,
		     0x01b1,0x02b1,0x01b7,0x01bb,0x01bd,0x20bd,0x00c0,0x01c0,0x08c1,
		     0x10c1,0x20c1,0x80c1,0x01c2,0x02c2,0x02c3,0x04c3,0x20c3,0x00c4,
		     0x01c4,0x02c4,0x04c4,0x08c4,0x10c4,0x20c4,0x40c4,0x00c5,0x01c5,
		     0x04c5,0x20c5,0x02ca,0x04ca,0x08ca,0x10ca,0x1eca,0x20cc,0x01cd,
		     0x02cd,0x11d0,0x12d0,0x21d0,0x41d0,0x42d0,0x81d0,0x82d0,0x01d1,
		     0x02d1,0x04d1,0x08d1,0x10d1,0x20d1,0x40d1,0x01d2,0x02d2,0x04d2,
		     0x08d2,0x01d3,0x1fe6,0x01f0,0x02f0,0x04f0,0x08f0,0x10f0,0x20f0,
		     0x40f0,0x80f0,0x01f1,0x02f1,0x04f1,0x07f1,0x01f2,0x02f2,0x04f2,
		     0x08f2,0x0af2};

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
