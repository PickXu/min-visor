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
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
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

//peh-x86svm-entry.S
//entry point for EMHF partition event-hub component for AMD x86 svm
//author: amit vasudevan (amitvasudevan@acm.org)

//----------------------------------------------------------------------
//globals referenced
	.extern g_midtable_numentries
	.extern g_midtable
	.extern xmhf_parteventhub_arch_x86svm_intercept_handler

//----------------------------------------------------------------------
//macros to save and restore GPRs
#define SAVEALL_GPRS \
        pushq	%rdi	; \
        pushq	%rsi	; \
	pushq	%rbp	; \
	pushq	%rsp    ; \
        pushq	%rbx	; \
        pushq	%rdx	; \
        pushq	%rcx	; \
        pushq	%rax	; 
	
#define RESTOREALL_GPRS \
	popq	%rax	; \
        popq	%rcx	; \
        popq	%rdx	; \
        popq	%rbx	; \
	popq	%rsp	; \
        popq	%rbp	; \
        popq	%rsi	; \
        popq	%rdi	; 


//----------------------------------------------------------------------
// xmhf_parteventhub_entry_x86svm
// we get control here right after any event within a partition
.section .text
.global xmhf_parteventhub_arch_x86svm_entry
xmhf_parteventhub_arch_x86svm_entry:
	
	//save EAX as it contains the VMCB address
	//pushl	%eax
	
	//step-1: save all CPU GPRs
	SAVEALL_GPRS
	
	//step-2: get hold of pointer to saved GPRs on stack
	movq %rsp, %rax
	
	//step-3: get VCPU * for this core (it is the first DWORD on
	//the core stack when we have an intercept, so move past the
	//saved GPRs, VMCB address and the return EIP for this function invocation)
	//movl 40(%esp), %esi
	movq 36(%rsp), %rsi
	
   	//step-4: invoke "C" handler
   	//1st argument is VCPU * followed by pointer to saved GPRs
    pushq %rax
    pushq %rsi
	call xmhf_parteventhub_arch_x86svm_intercept_handler
    addq $0x08, %rsp

	//step-5: restore all CPU GPRs
	RESTOREALL_GPRS
		
	//restore VMCB address
	//popl	%eax
	
	//return
	ret
