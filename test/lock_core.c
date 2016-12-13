#include "lock_core.h"

int lock_core(void) {
    int eax, ebx, ecx;
    // LOCK VCPU
    eax = 24;
    ebx = ecx = 0;
    asm volatile("vmcall\n"
		:
		: "a" (eax), "b" (ebx), "c" (ecx)
		);

    return 0;   
}    

int unlock_core(void) {
    int eax, ebx, ecx;
    // UNLOCK VCPU
    eax = 25;
    ebx = ecx = 0;
    asm volatile("vmcall\n"
		:
		: "a" (eax), "b" (ebx), "c" (ecx)
		);

    return 0;
}
