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

// EMHF secure loader component declarations
// author: amit vasudevan (amitvasudevan@acm.org)

#ifndef __EMHF_SL_H__
#define __EMHF_SL_H__


#ifndef __ASSEMBLY__

//----------------------------------------------------------------------
//exported DATA 
//----------------------------------------------------------------------
extern u64 sl_baseaddr;	


//----------------------------------------------------------------------
//exported FUNCTIONS 
//----------------------------------------------------------------------


//----------------------------------------------------------------------
//ARCH. BACKENDS
//----------------------------------------------------------------------
void* xmhf_sl_arch_hva2sla(uintptr_t x);
u64 xmhf_sl_arch_sla2spa(void* x);
bool xmhf_sl_arch_integrity_check(u8* runtime_base_addr, size_t runtime_len);
void xmhf_sl_arch_sanitize_post_launch(void);
void xmhf_sl_arch_early_dmaprot_init(u64 runtime_size);
void xmhf_sl_arch_xfer_control_to_runtime(RPB * rpb);


//----------------------------------------------------------------------
//x86 ARCH. INTERFACES
//----------------------------------------------------------------------
u64 xmhf_sl_arch_x86_setup_runtime_paging(RPB * rpb, u64 runtime_spa, u64 runtime_sva, u64 totalsize);
void xmhf_sl_arch_x86_invoke_runtime_entrypoint(u64 gdtbase, u64 idtbase,
	u64 entrypoint, u64 stacktop, u64 cr3); 


//----------------------------------------------------------------------
//x86vmx SUBARCH. INTERFACES
//----------------------------------------------------------------------


//----------------------------------------------------------------------
//x86svm SUBARCH. INTERFACES
//----------------------------------------------------------------------
extern u64 g_sl_protected_dmabuffer[]; //protected DMA-protection buffer 
									   //for early DMA protection 
									   //(only used for x86svm)
									   

#endif	//__ASSEMBLY__

#endif //__EMHF_SL_H__
