#include <stdio.h>
#include <stdint.h>

int main(int argc, char** argv) {
    int eax, ebx, ecx;
    //int target=10000000,cur=0;
    // LOCK VCPU
    eax = 24;
    asm volatile("vmcall\n"
		:
		: "a" (eax), "b" (ebx), "c" (ecx)
		);

    
    
    //while(cur < target) cur++ ;
    while(1) ;

    // UNLOCK VCPU
    eax = 25;
    asm volatile("vmcall\n"
		:
		: "a" (eax), "b" (ebx), "c" (ecx)
		);

    return 0;
}
