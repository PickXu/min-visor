/*
 * @XMHF_LICENSE_HEADER_START@
 *
 * eXtensible, Modular Hypervisor Framework (XMHF)
 * Copyright (c) 2009-2012 Carnegie Mellon University
 * Copyright (c) 2010-2012 VDG Inc.
 * All Rights Reserved.
 *
 * Developed by: XMHF Team
 *               Carnegie Mellon University / CyLab
 *               VDG Inc.
 *               http://xmhf.org
 *
 * Rrdistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Rrdistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Rrdistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 *
 * Neither the names of Carnegie Mellon or VDG Inc, nor the names of
 * its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * @XMHF_LICENSE_HEADER_END@
 */

//processor.h - CPU declarations
//author: amit vasudevan (amitvasudevan@acm.org)
#ifndef __PROCESSOR_H
#define __PROCESSOR_H

#define CPU_VENDOR_INTEL 	0xAB
#define CPU_VENDOR_AMD 		0xCD

#define AMD_STRING_DWORD1 0x68747541
#define AMD_STRING_DWORD2 0x69746E65
#define AMD_STRING_DWORD3 0x444D4163

#define INTEL_STRING_DWORD1	0x756E6547
#define INTEL_STRING_DWORD2	0x49656E69
#define INTEL_STRING_DWORD3	0x6C65746E	

#define EFLAGS_CF	0x00000001 /* Carry Flag */
#define EFLAGS_PF	0x00000004 /* Parity Flag */
#define EFLAGS_AF	0x00000010 /* Auxillary carry Flag */
#define EFLAGS_ZF	0x00000040 /* Zero Flag */
#define EFLAGS_SF	0x00000080 /* Sign Flag */
#define EFLAGS_TF	0x00000100 /* Trap Flag */
#define EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define EFLAGS_DF	0x00000400 /* Direction Flag */
#define EFLAGS_OF	0x00000800 /* Overflow Flag */
#define EFLAGS_IOPL	0x00003000 /* IOPL mask */
#define EFLAGS_NT	0x00004000 /* Nested Task */
#define EFLAGS_RF	0x00010000 /* Resume Flag */
#define EFLAGS_VM	0x00020000 /* Virtual Mode */
#define EFLAGS_AC	0x00040000 /* Alignment Check */
#define EFLAGS_VIF	0x00080000 /* Virtual Interrupt Flag */
#define EFLAGS_VIP	0x00100000 /* Virtual Interrupt Pending */
#define EFLAGS_ID	0x00200000 /* CPUID detection flag */

#define CR0_PE              0x00000001 /* Enable Protected Mode    (RW) */
#define CR0_MP              0x00000002 /* Monitor Coprocessor      (RW) */
#define CR0_EM              0x00000004 /* Require FPU Emulation    (RO) */
#define CR0_TS              0x00000008 /* Task Switched            (RW) */
#define CR0_ET              0x00000010 /* Extension type           (RO) */
#define CR0_NE              0x00000020 /* Numeric Error Reporting  (RW) */
#define CR0_WP              0x00010000 /* Supervisor Write Protect (RW) */
#define CR0_AM              0x00040000 /* Alignment Checking       (RW) */
#define CR0_NW              0x20000000 /* Not Write-Through        (RW) */
#define CR0_CD              0x40000000 /* Cache Disable            (RW) */
#define CR0_PG              0x80000000 /* Paging                   (RW) */

#define CR4_VME		0x0001	/* enable vm86 extensions */
#define CR4_PVI		0x0002	/* virtual interrupts flag enable */
#define CR4_TSD		0x0004	/* disable time stamp at ipl 3 */
#define CR4_DE		0x0008	/* enable debugging extensions */
#define CR4_PSE		0x0010	/* enable page size extensions */
#define CR4_PAE		0x0020	/* enable physical address extensions */
#define CR4_MCE		0x0040	/* Machine check enable */
#define CR4_PGE		0x0080	/* enable global pages */
#define CR4_PCE		0x0100	/* enable performance counters at ipl 3 */
#define CR4_OSFXSR		0x0200	/* enable fast FPU save and restore */
#define CR4_OSXMMEXCPT	0x0400	/* enable unmasked SSE exceptions */
#define CR4_VMXE		0x2000  /* enable VMX */
#define CR4_SMXE		0x4000  /* enable SMX */
#define CR4_OSXSAVE	(1UL << 18)	// XSAVE and Processor Extended States Enable bit

//CPUID related
#define EDX_PAE 6
#define EDX_NX 20
#define ECX_SVM 2
#define EDX_NP 0

#define SVM_CPUID_FEATURE       (1 << 2)

#define CPUID_X86_FEATURE_VMX    (1<<5)
#define CPUID_X86_FEATURE_SMX    (1<<6)

//CPU exception numbers
//(intel SDM vol 3a 6-27)
#define	CPU_EXCEPTION_DE				0			//divide error exception
#define CPU_EXCEPTION_DB				1			//debug exception
#define	CPU_EXCEPTION_NMI				2			//non-maskable interrupt
#define	CPU_EXCEPTION_BP				3			//breakpoint exception
#define	CPU_EXCEPTION_OF				4			//overflow exception
#define	CPU_EXCEPTION_BR				5			//bound-range exceeded
#define	CPU_EXCEPTION_UD				6			//invalid opcode
#define	CPU_EXCEPTION_NM				7			//device not available
#define	CPU_EXCEPTION_DF				8			//double fault exception (code)
#define	CPU_EXCEPTION_RESV9				9			//reserved
#define	CPU_EXCEPTION_TS				10			//invalid TSS (code)
#define	CPU_EXCEPTION_NP				11			//segment not present (code)
#define	CPU_EXCEPTION_SS				12			//stack fault (code)
#define	CPU_EXCEPTION_GP				13			//general protection (code)
#define CPU_EXCEPTION_PF				14			//page fault (code)
#define	CPU_EXCEPTION_RESV15			15			//reserved
#define CPU_EXCEPTION_MF				16			//floating-point exception
#define CPU_EXCEPTION_AC				17			//alignment check (code)
#define CPU_EXCEPTION_MC				18			//machine check
#define CPU_EXCEPTION_XM				19			//SIMD floating point exception


//extended control registers
#define XCR_XFEATURE_ENABLED_MASK       0x00000000


#ifndef __ASSEMBLY__

//x86 GPR set definition (follows the order enforced by PUSHAD/POPAD
//SDM Vol 2B. 4-427)
struct regs
{
  u64 rdi;
  u64 rsi;
  u64 rbp;
  u64 rsp;
  u64 rbx;
  u64 rdx;
  u64 rcx;
  u64 rax;
}__attribute__ ((packed));


typedef struct {
  u16 isrLow;
  u16 isrSelector;
  u8  count;
  u8  type;
  u16 isrHigh;
} __attribute__ ((packed)) idtentry_t;

typedef struct {
  unsigned short limit0_15;
  unsigned short baseAddr0_15;
  unsigned char baseAddr16_23;
  unsigned char attributes1;
  unsigned char limit16_19attributes2;    
  unsigned char baseAddr24_31;
} __attribute__ ((packed)) TSSENTRY;


#define get_eflags(x)  __asm__ __volatile__("pushfq ; popq %0 ":"=g" (x): /* no input */ :"memory")
#define set_eflags(x) __asm__ __volatile__("pushq %0 ; popfq": /* no output */ :"g" (x):"memory", "cc")

#define cpuid(op, rax, rbx, rcx, rdx)		\
({						\
  __asm__ __volatile__("cpuid"				\
          :"=a"(*(rax)), "=b"(*(rbx)), "=c"(*(rcx)), "=d"(*(rdx))	\
          :"0"(op), "2" (0));			\
})


#define rdtsc(rax, rdx)		\
({						\
  __asm__ __volatile__ ("rdtsc"				\
          :"=a"(*(rax)), "=d"(*(rdx))	\
          :);			\
})

static inline uint64_t rdtsc64(void)
{
        uint64_t rv;

        __asm__ __volatile__ ("rdtsc" : "=A" (rv));
        return (rv);
}


/* Calls to read and write control registers */ 
static inline unsigned long read_cr0(void){
  unsigned long __cr0;
  __asm__("mov %%cr0,%0\n\t" :"=r" (__cr0));
  return __cr0;
}

static inline void write_cr0(unsigned long val){
  __asm__("mov %0,%%cr0": :"r" ((unsigned long)val));
}

static inline unsigned long read_cr3(void){
  unsigned long __cr3;
  __asm__("mov %%cr3,%0\n\t" :"=r" (__cr3));
  return __cr3;
}

static inline unsigned long read_rsp(void){
  unsigned long __rsp;
  __asm__("mov %%rsp,%0\n\t" :"=r" (__rsp));
  return __rsp;
}

static inline unsigned long read_rbp(void){
  unsigned long __rbp;
  __asm__("mov %%rbp,%0\n\t" :"=r" (__rbp));
  return __rbp;
}

static inline void write_cr3(unsigned long val){
  __asm__("mov %0,%%cr3\n\t"
          "jmp 1f\n\t"
          "1:"
          : 
          :"r" ((unsigned long)val));
}

static inline unsigned long read_cr2(void){
  unsigned long __cr2;
  __asm__("mov %%cr2,%0\n\t" :"=r" (__cr2));
  return __cr2;
}

static inline unsigned long read_cr4(void){
  unsigned long __cr4;
  __asm__("mov %%cr4,%0\n\t" :"=r" (__cr4));
  return __cr4;
}

static inline void write_cr4(unsigned long val){
  __asm__("mov %0,%%cr4": :"r" ((unsigned long)val));
}

static inline void skinit(unsigned long rax) {
    __asm__("mov %0, %%rax": :"r" (rax));
    __asm__("skinit":);
}


//segment register access
static inline u64 read_segreg_cs(void){
  u64 __cs;
  __asm__("mov %%cs, %0 \r\n" :"=r" (__cs));
  return __cs;
}

static inline u64 read_segreg_ds(void){
  u64 __ds;
  __asm__("mov %%ds, %0 \r\n" :"=r" (__ds));
  return __ds;
}

static inline u64 read_segreg_es(void){
  u64 __es;
  __asm__("mov %%es, %0 \r\n" :"=r" (__es));
  return __es;
}

static inline u64 read_segreg_fs(void){
  u64 __fs;
  __asm__("mov %%fs, %0 \r\n" :"=r" (__fs));
  return __fs;
}

static inline u64 read_segreg_gs(void){
  u64 __gs;
  __asm__("mov %%gs, %0 \r\n" :"=r" (__gs));
  return __gs;
}

static inline u64 read_segreg_ss(void){
  u64 __ss;
  __asm__("mov %%ss, %0 \r\n" :"=r" (__ss));
  return __ss;
}

static inline u16 read_tr_sel(void){
  u16 __trsel;
  __asm__("str %0 \r\n" :"=r" (__trsel));
  return __trsel;
}

static inline void wbinvd(void)
{
    __asm__ __volatile__ ("wbinvd");
}

static inline uint64_t bsrl(uint64_t mask)
{
    uint64_t   result;

    __asm__ __volatile__ ("bsrq %1,%0" : "=r" (result) : "rm" (mask) : "cc");
    return (result);
}

static inline int fls(int mask)
{
    return (mask == 0 ? mask : (int)bsrl((u64)mask) + 1);
}

static inline void disable_intr(void)
{
    __asm__ __volatile__ ("cli" : : : "memory");
}

static inline void enable_intr(void)
{
    __asm__ __volatile__ ("sti");
}

//get extended control register (xcr)
static inline u64 xgetbv(u64 xcr_reg){
	u64 rax, rdx;

	asm volatile(".byte 0x0f,0x01,0xd0"
			: "=a" (rax), "=d" (rdx)
			: "c" (xcr_reg));

	return ((u64)rdx << 32) + (u64)rax;
}

//set extended control register (xcr)
static inline void xsetbv(u64 xcr_reg, u64 value){
	u64 rax = (u64)value;
	u64 rdx = value >> 32;

	asm volatile(".byte 0x0f,0x01,0xd1"
			:
			: "a" (rax), "d" (rdx), "c" (xcr_reg));
}

#ifndef __XMHF_VERIFICATION__

	static inline u64 get_cpu_vendor_or_die(void) {
	    u64 dummy;
	    u64 vendor_dword1, vendor_dword2, vendor_dword3;
	    
	    cpuid(0, &dummy, &vendor_dword1, &vendor_dword3, &vendor_dword2);
	    if(vendor_dword1 == AMD_STRING_DWORD1 && vendor_dword2 == AMD_STRING_DWORD2
	       && vendor_dword3 == AMD_STRING_DWORD3)
		return CPU_VENDOR_AMD;
	    else if(vendor_dword1 == INTEL_STRING_DWORD1 && vendor_dword2 == INTEL_STRING_DWORD2
		    && vendor_dword3 == INTEL_STRING_DWORD3)
		return CPU_VENDOR_INTEL;
	    else
		HALT();

	    return 0; // never reached 
	}


	void spin_lock(volatile u64 *);
	void spin_unlock(volatile u64 *);

#else //__XMHF_VERIFICATION__

	static inline u64 get_cpu_vendor_or_die(void) {
			extern u64 xmhf_verify_cpu_vendor;
			return xmhf_verify_cpu_vendor;
	}

	inline void spin_lock(volatile u64 *lock){
			(void)lock;
	}

	inline void spin_unlock(volatile u64 *lock){
			(void)lock;
	}

#endif //__XMHF_VERIFICATION__



#endif //__ASSEMBLY__

#endif /* __PROCESSOR_H */
