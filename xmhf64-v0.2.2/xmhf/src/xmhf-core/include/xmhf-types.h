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

//types.h - base types
#ifndef __EMHF_TYPES_H_
#define __EMHF_TYPES_H_


#ifndef __ASSEMBLY__

typedef u64 	paddr_t;		//physical address
typedef void* 	hva_t; 			//hypervisor virtual address 
typedef u64 	spa_t; 			//system physical address 
typedef u64 	gva_t; 			//guest virtual address. we only support 32-bit guests 
typedef u64 	gpa_t; 			//guest physical address. can be 64-bit with PAE 


//"golden" digest values injected using CFLAGS during build process
//NOTE: NO WAY TO SELF-CHECK slbelow64K; JUST A SANITY-CHECK
typedef struct _integrity_measurement_values {
    u8 sha_slbelow64K[20]; // TODO: play nice with SHA_DIGEST_LENGTH in sha1.h
    u8 sha_slabove64K[20];
    u8 sha_runtime[20];
} INTEGRITY_MEASUREMENT_VALUES;


//"runtime" parameter block structure; arch_rpb (in startup component) 
//is the default definition
typedef struct {
	u64 magic;
	u64 XtVmmEntryPoint;
	u64 XtVmmPdptBase;
	u64 XtVmmPdtsBase;
	u64 XtGuestOSBootModuleBase;
	u64 XtGuestOSBootModuleSize;
	u64 runtime_appmodule_base;
	u64 runtime_appmodule_size;
	u64 XtVmmStackBase;
	u64 XtVmmStackSize;
	u64 XtVmmGdt;
	u64 XtVmmIdt;
	u64 XtVmmIdtFunctionPointers;
	u64 XtVmmIdtEntries;
	u64 XtVmmRuntimePhysBase;
	u64 XtVmmRuntimeVirtBase;
	u64 XtVmmRuntimeSize;
	u64 XtVmmE820Buffer;
	u64 XtVmmE820NumEntries;
	u64 XtVmmMPCpuinfoBuffer;
	u64 XtVmmMPCpuinfoNumEntries;
	u64 XtVmmTSSBase;
    uart_config_t RtmUartConfig;	        /* runtime options parsed in init and passed forward */
    char cmdline[1024]; 				/* runtime options parsed in init and passed forward */
	u64 isEarlyInit;					//1 for an "early init" else 0 (late-init)
} __attribute__((packed)) RPB, *PRPB;


//"sl" parameter block structure 
typedef struct _sl_parameter_block {
	u64 magic;						//magic identifier
	u64 errorHandler;				//error handler (currently unused)
	u64 isEarlyInit;				//"early" or "late" init
	u64 numE820Entries;				//number of E820 entries
	u8  memmapbuffer[1280];			//max. 64 entries of 20 bytes each describing the system memory map
	u64 numCPUEntries;				//number of cores
	u8  cpuinfobuffer[128];			//max. 8 entries of 16 bytes each describing each physical core in the system
	u64 runtime_size;				//size of the runtime image
	u64 runtime_osbootmodule_base;	//guest OS bootmodule base
	u64 runtime_osbootmodule_size;	//guest OS bootmodule size
	u64 runtime_appmodule_base;		//XMHF hypapp optional module base
	u64 runtime_appmodule_size;		//XMHF hypapp optional module size
    u64 rdtsc_before_drtm;			// Performance measurements related to DRTM
    u64 rdtsc_after_drtm;

    /* runtime options parsed in init and passed forward */
    uart_config_t uart_config;
    char cmdline[1024]; /* runtime options parsed in init and passed forward */
} __attribute__((packed)) SL_PARAMETER_BLOCK;





#endif /*ifndef __ASSEMBLY__*/

#endif /* __EMHF_TYPES_H_ */
