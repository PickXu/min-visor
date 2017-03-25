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

// islayer low-level support for VMX
// author: amit vasudevan (amitvasudevan@acm.org)

#include <xmhf.h> 

//---globals and externs referenced by this module------------------------------------------
.extern x_gdt_start

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
 
.section .text

//----------------------------------------------------------------------
// start HVM on a given physical core
// on success: this function will not return
// on failure: 1 if a valid error code is present, 0 if no error code, 
// 2 if invalid error info. (should never happen)
//----------------------------------------------------------------------
	.global __vmx_start_hvm
	__vmx_start_hvm:
	
	//save GPRs
	//pushal
	SAVEALL_GPRS
   
	//real-mode setup just like the BIOS
	movq $0x0, %rax
	movq $0x0, %rbx
	movq $0x0, %rcx
	movq $0x80, %rdx
	movq $0x0, %rbp
	movq $0x0, %rsi
	movq $0x0, %rdi

	//attempt to instantiate the HVM
	vmlaunch
	 
	//if we get here then some error happened during the launch
	
	//restore stack frame for a return from this procedure
	//popal	
	RESTOREALL_GPRS

	//there are two possible causes of failure, VMFailInvalid or
	//VMFailValid (VM instruction error field contains the error code)
	//check which happened and return appropriate value in eax 
	jc __vmx_start_hvm_failinvalid
	
	jnz	__vmx_start_hvm_undefinedimplementation	
	movq $0x1, %rax
	ret					//return 1 as we have error code

__vmx_start_hvm_undefinedimplementation:
	movq $0x2, %rax		//violation of VMLAUNCH specs., handle it anyways
	ret

__vmx_start_hvm_failinvalid:
	xor %rax, %rax		//return 0 as we have no error code available
	ret
