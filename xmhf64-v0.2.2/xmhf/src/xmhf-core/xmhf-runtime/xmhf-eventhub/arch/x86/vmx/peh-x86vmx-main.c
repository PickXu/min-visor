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

// peh-x86vmx-main.c
// EMHF partition event-hub for Intel x86 vmx
// author: amit vasudevan (amitvasudevan@acm.org)
#include <xmhf.h> 


//---VMX decode assist----------------------------------------------------------
//map a CPU register index into appropriate VCPU *vcpu or struct regs *r field 
//and return the address of the field
static u64 * _vmx_decode_reg(u64 gpr, VCPU *vcpu, struct regs *r){
  if ( ((int)gpr >=0) && ((int)gpr <= 7) ){
  
	  switch(gpr){
		case 0: return ( (u64 *)&r->rax );
		case 1: return ( (u64 *)&r->rcx );
		case 2: return ( (u64 *)&r->rdx );
		case 3: return ( (u64 *)&r->rbx );
		case 4: return ( (u64 *)&vcpu->vmcs.guest_RSP);
		case 5: return ( (u64 *)&r->rbp );
		case 6: return ( (u64 *)&r->rsi );
		case 7: return ( (u64 *)&r->rdi );
	  }
   }else{
		printf("\n[%02x]%s: invalid gpr value (%u). halting!", vcpu->id,
			__FUNCTION__, gpr);
		HALT();
   }

	//we will never get here, appease the compiler
	return (u64 *)&r->rax;
}


//---intercept handler (CPUID)--------------------------------------------------
static void _vmx_handle_intercept_cpuid(VCPU *vcpu, struct regs *r){
	asm volatile ("cpuid\r\n"
          :"=a"(r->rax), "=b"(r->rbx), "=c"(r->rcx), "=d"(r->rdx)
          :"a"(r->rax), "c" (r->rcx));
	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;
}


//---vmx int 15 intercept handler-----------------------------------------------
static void _vmx_int15_handleintercept(VCPU *vcpu, struct regs *r){
	u16 cs, ip;
	u8 *bdamemory = (u8 *)0x4AC;

	//if in V86 mode translate the virtual address to physical address
	if( (vcpu->vmcs.guest_CR0 & CR0_PE) && (vcpu->vmcs.guest_CR0 & CR0_PG) &&
			(vcpu->vmcs.guest_RFLAGS & EFLAGS_VM) ){
		u8 *bdamemoryphysical;
		#ifdef __XMHF_VERIFICATION__
			bdamemoryphysical = (u8 *)nondet_u64();
		#else
			bdamemoryphysical = (u8 *)xmhf_smpguest_arch_x86vmx_walk_pagetables(vcpu, (u64)bdamemory);
		#endif
		if((u64)bdamemoryphysical < rpb->XtVmmRuntimePhysBase){
			printf("\nINT15 (E820): V86 mode, bdamemory translated from %08x to %08x",
				(u64)bdamemory, (u64)bdamemoryphysical);
			bdamemory = bdamemoryphysical; 		
		}else{
			printf("\nCPU(0x%02x): INT15 (E820) V86 mode, translated bdamemory points beyond \
				guest physical memory space. Halting!", vcpu->id);
			HALT();
		}
	}


	//if E820 service then...
	if((u16)r->rax == 0xE820){
		//AX=0xE820, EBX=continuation value, 0 for first call
		//ES:DI pointer to buffer, ECX=buffer size, EDX='SMAP'
		//return value, CF=0 indicated no error, EAX='SMAP'
		//ES:DI left untouched, ECX=size returned, EBX=next continuation value
		//EBX=0 if last descriptor
		printf("\nCPU(0x%02x): INT 15(e820): AX=0x%04x, EDX=0x%08x, EBX=0x%08x, ECX=0x%08x, ES=0x%04x, DI=0x%04x", vcpu->id, 
		(u16)r->rax, r->rdx, r->rbx, r->rcx, (u16)vcpu->vmcs.guest_ES_selector, (u16)r->rdi);
		
		//HALT_ON_ERRORCOND(r->rdx == 0x534D4150UL);  //'SMAP' should be specified by guest
		//HALT_ON_ERRORCOND(r->rbx < rpb->XtVmmE820NumEntries); //invalid continuation value specified by guest!
		if( (r->rdx == 0x534D4150UL) && (r->rbx < rpb->XtVmmE820NumEntries) ){
			
			//copy the e820 descriptor and return its size in ECX
			{
				
				if( ((u64)(vcpu->vmcs.guest_ES_base+(u16)r->rdi)) < rpb->XtVmmRuntimePhysBase){
					#ifdef __XMHF_VERIFICATION__
						GRUBE820 pe820entry;
						pe820entry.baseaddr_low = g_e820map[r->rbx].baseaddr_low;
						pe820entry.baseaddr_high = g_e820map[r->rbx].baseaddr_high;
						pe820entry.length_low = g_e820map[r->rbx].length_low;
						pe820entry.length_high = g_e820map[r->rbx].length_high;
						pe820entry.type = g_e820map[r->rbx].type;
					#else
						GRUBE820 *pe820entry;
						pe820entry = (GRUBE820 *)((u64)(vcpu->vmcs.guest_ES_base+(u16)r->rdi));
						pe820entry->baseaddr_low = g_e820map[r->rbx].baseaddr_low;
						pe820entry->baseaddr_high = g_e820map[r->rbx].baseaddr_high;
						pe820entry->length_low = g_e820map[r->rbx].length_low;
						pe820entry->length_high = g_e820map[r->rbx].length_high;
						pe820entry->type = g_e820map[r->rbx].type;
					#endif //__XMHF_VERIFICATION__
				}else{
						printf("\nCPU(0x%02x): INT15 E820. Guest buffer is beyond guest \
							physical memory bounds. Halting!", vcpu->id);
						HALT();
				}
						
			}
			r->rcx=20;

			//set EAX to 'SMAP' as required by the service call				
			r->rax=r->rdx;

			//we need to update carry flag in the guest EFLAGS register
			//however since INT 15 would have pushed the guest FLAGS on stack
			//we cannot simply reflect the change by modifying vmcb->rflags
			//instead we need to make the change to the pushed FLAGS register on
			//the guest stack. the real-mode IRET frame looks like the following 
			//when viewed at top of stack
			//guest_ip		(16-bits)
			//guest_cs		(16-bits)
			//guest_flags (16-bits)
			//...
		
			{
				//u16 guest_cs, guest_ip, guest_flags;
				u16 guest_cs __attribute__((unused)), guest_ip __attribute__((unused)), guest_flags;
				u16 *gueststackregion = (u16 *)( (u64)vcpu->vmcs.guest_SS_base + (u16)vcpu->vmcs.guest_RSP );
			
			
				//if V86 mode translate the virtual address to physical address
				if( (vcpu->vmcs.guest_CR0 & CR0_PE) && (vcpu->vmcs.guest_CR0 & CR0_PG) &&
					(vcpu->vmcs.guest_RFLAGS & EFLAGS_VM) ){
					#ifdef __XMHF_VERIFICATION__
						u8 *gueststackregionphysical = (u8 *)nondet_u64();
					#else
						u8 *gueststackregionphysical = (u8 *)xmhf_smpguest_arch_x86vmx_walk_pagetables(vcpu, (u64)gueststackregion);
					#endif
					if((u64)gueststackregionphysical < rpb->XtVmmRuntimePhysBase){
						printf("\nINT15 (E820): V86 mode, gueststackregion translated from %08x to %08x",
							(u64)gueststackregion, (u64)gueststackregionphysical);
						gueststackregion = (u16 *)gueststackregionphysical; 		
					}else{
						printf("\nCPU(0x%02x): INT15 (E820) V86 mode, translated gueststackregion points beyond \
							guest physical memory space. Halting!", vcpu->id);
						HALT();
					}
				}
			
				
				//get guest IP, CS and FLAGS from the IRET frame
				#ifdef __XMHF_VERIFICATION__
					guest_ip = nondet_u16();
					guest_cs = nondet_u16();
					guest_flags = nondet_u16();
				#else
					guest_ip = gueststackregion[0];
					guest_cs = gueststackregion[1];
					guest_flags = gueststackregion[2];
				#endif	//__XMHF_VERIFICATION__

		
				//increment e820 descriptor continuation value
				r->rbx=r->rbx+1;
						
				if(r->rbx > (rpb->XtVmmE820NumEntries-1) ){
					//we have reached the last record, so set CF and make EBX=0
					r->rbx=0;
					guest_flags |= (u16)EFLAGS_CF;
					#ifndef __XMHF_VERIFICATION__
						gueststackregion[2] = guest_flags;
					#endif
				}else{
					//we still have more records, so clear CF
					guest_flags &= ~(u16)EFLAGS_CF;
					#ifndef __XMHF_VERIFICATION__
						gueststackregion[2] = guest_flags;
					#endif
				}
			  
			}
			
		}else{	//invalid state specified during INT 15 E820, fail by
				//setting carry flag
				printf("\nCPU(0x%02x): INT15 (E820), invalid state specified by guest \
						Halting!", vcpu->id);
				HALT();
		}
		
		//update RIP to execute the IRET following the VMCALL instruction
		//effectively returning from the INT 15 call made by the guest
		vcpu->vmcs.guest_RIP += 3;
	
		return;
	} //E820 service
	
	//ok, this is some other INT 15h service, so simply chain to the original
	//INT 15h handler

#ifdef __XMHF_VERIFICATION__	
	//get IP and CS of the original INT 15h handler
	ip = nondet_u16();
	cs = nondet_u16();
#else
	//get IP and CS of the original INT 15h handler
	ip = *((u16 *)((u64)bdamemory + 4));
	cs = *((u16 *)((u64)bdamemory + 6));
#endif
	
	//update VMCS with the CS and IP and let go
	vcpu->vmcs.guest_RIP = ip;
	vcpu->vmcs.guest_CS_base = cs * 16;
	vcpu->vmcs.guest_CS_selector = cs;		 
}




//------------------------------------------------------------------------------
// guest MSR r/w intercept handling
// HAL invokes NT kernel via SYSENTER if CPU supports it. However,
// regular apps using NTDLL will still use INT 2E if registry entry is not
// tweaked. So, we HAVE to emulate SYSENTER_CS/EIP/ESP to ensure that
// NT kernel doesnt panic with SESSION5_INITIALIZATION_FAILED!
//
// This took me nearly a month of disassembly into the HAL, 
// NTKERNEL and debugging to figure out..eh? 
//
// AMD SVM is neater, only
// when you ask for these MSR intercepts do they get stored and read from
// the VMCB. However, for Intel regardless they get stored and read from VMCS
// for the guest. So we need to have these intercepts bare minimum!!
// A line to this effect would have been much appreciated in the Intel manuals
// doh!!!
//------------------------------------------------------------------------------
  
//---intercept handler (WRMSR)--------------------------------------------------
static void _vmx_handle_intercept_wrmsr(VCPU *vcpu, struct regs *r){
	//printf("\nCPU(0x%02x): WRMSR 0x%08x", vcpu->id, r->rcx);

	switch(r->rcx){
		case IA32_SYSENTER_CS_MSR:
			vcpu->vmcs.guest_SYSENTER_CS = (unsigned int)r->rax;
			break;
		case IA32_SYSENTER_EIP_MSR:
			vcpu->vmcs.guest_SYSENTER_EIP = (unsigned long long)r->rax;
			break;
		case IA32_SYSENTER_ESP_MSR:
			vcpu->vmcs.guest_SYSENTER_ESP = (unsigned long long)r->rax;
			break;
		default:{
			asm volatile ("wrmsr\r\n"
          : //no outputs
          :"a"(r->rax), "c" (r->rcx), "d" (r->rdx));	
			break;
		}
	}
	
	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;
	//printf("\nCPU(0x%02x): WRMSR end", vcpu->id);
}

//---intercept handler (RDMSR)--------------------------------------------------
static void _vmx_handle_intercept_rdmsr(VCPU *vcpu, struct regs *r){
	//printf("\nCPU(0x%02x): RDMSR 0x%08x", vcpu->id, r->rcx);

	switch(r->rcx){
		case IA32_SYSENTER_CS_MSR:
			r->rax = (u64)vcpu->vmcs.guest_SYSENTER_CS;
			r->rdx = 0;
			break;
		case IA32_SYSENTER_EIP_MSR:
			r->rax = (u64)vcpu->vmcs.guest_SYSENTER_EIP;
			r->rdx = 0;
			break;
		case IA32_SYSENTER_ESP_MSR:
			r->rax = (u64)vcpu->vmcs.guest_SYSENTER_ESP;
			r->rdx = 0;
			break;
		default:{
			asm volatile ("rdmsr\r\n"
          : "=a"(r->rax), "=d"(r->rdx)
          : "c" (r->rcx));
			break;
		}
	}
	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;

	//printf("\nCPU(0x%02x): RDMSR (0x%08x)=0x%08x%08x", vcpu->id, r->rcx, r->rdx, r->rax);
}


//---intercept handler (EPT voilation)----------------------------------
static void _vmx_handle_intercept_eptviolation(VCPU *vcpu, struct regs *r){
	u64 errorcode;
        u64	gpa, gva;
	errorcode = (u64)vcpu->vmcs.info_exit_qualification;
	gpa = (u64) vcpu->vmcs.guest_paddr_full;
	gva = (u64) vcpu->vmcs.info_guest_linear_address;

	//check if EPT violation is due to LAPIC interception
	if(vcpu->isbsp && (gpa >= g_vmx_lapic_base) && (gpa < (g_vmx_lapic_base + PAGE_SIZE_4K)) ){
		xmhf_smpguest_arch_x86_eventhandler_hwpgtblviolation(vcpu, gpa, errorcode);
	}else{ //no, pass it to hypapp 
		xmhf_smpguest_arch_x86vmx_quiesce(vcpu);
		xmhf_app_handleintercept_hwpgtblviolation(vcpu, r, gpa, gva,
				(errorcode & 7));
		xmhf_smpguest_arch_x86vmx_endquiesce(vcpu);
	}		
}


//---intercept handler (I/O port access)----------------------------------------
static void _vmx_handle_intercept_ioportaccess(VCPU *vcpu, struct regs *r){
  u64 access_size, access_type, portnum, stringio;
	u64 app_ret_status = APP_IOINTERCEPT_CHAIN;
	
  access_size = (u64)vcpu->vmcs.info_exit_qualification & 0x00000007UL;
	access_type = ((u64)vcpu->vmcs.info_exit_qualification & 0x00000008UL) >> 3;
	portnum =  ((u64)vcpu->vmcs.info_exit_qualification & 0xFFFF0000UL) >> 16;
	stringio = ((u64)vcpu->vmcs.info_exit_qualification & 0x00000010UL) >> 4;
	
  HALT_ON_ERRORCOND(!stringio);	//we dont handle string IO intercepts

  //call our app handler, TODO: it should be possible for an app to
  //NOT want a callback by setting up some parameters during appmain
	xmhf_smpguest_arch_x86vmx_quiesce(vcpu);
	app_ret_status=xmhf_app_handleintercept_portaccess(vcpu, r, portnum, access_type, 
          access_size);
    xmhf_smpguest_arch_x86vmx_endquiesce(vcpu);

  if(app_ret_status == APP_IOINTERCEPT_CHAIN){
   	if(access_type == IO_TYPE_OUT){
  		if( access_size== IO_SIZE_BYTE)
  				outb((u8)r->rax, portnum);
  		else if (access_size == IO_SIZE_WORD)
  				outw((u16)r->rax, portnum);
  		else if (access_size == IO_SIZE_DWORD)
  				outl((u64)r->rax, portnum);	
  	}else{
  		if( access_size== IO_SIZE_BYTE){
  				r->rax &= 0xFFFFFF00UL;	//clear lower 8 bits
  				r->rax |= (u8)inb(portnum);
  		}else if (access_size == IO_SIZE_WORD){
  				r->rax &= 0xFFFF0000UL;	//clear lower 16 bits
  				r->rax |= (u16)inw(portnum);
  		}else if (access_size == IO_SIZE_DWORD){
  				r->rax = (u64)inl(portnum);	
  		}
  	}
  	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;

  }else{
    //skip the IO instruction, app has taken care of it
  	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;
  }

	return;
}

//---CR0 access handler-------------------------------------------------
static void vmx_handle_intercept_cr0access_ug(VCPU *vcpu, struct regs *r, u64 gpr, u64 tofrom){
	u64 cr0_value;
	
	HALT_ON_ERRORCOND(tofrom == VMX_CRX_ACCESS_TO);
	
	cr0_value = *((u64 *)_vmx_decode_reg(gpr, vcpu, r));

	//printf("\n[cr0-%02x] MOV TO, current=0x%08x, proposed=0x%08x", vcpu->id,
	//	(u64)vcpu->vmcs.guest_CR0, cr0_value);

	vcpu->vmcs.control_CR0_shadow = cr0_value;
	vcpu->vmcs.guest_CR0 = cr0_value & ~(CR0_CD | CR0_NW);
	
	//flush mappings
	xmhf_memprot_arch_x86vmx_flushmappings(vcpu);
}

//---CR4 access handler---------------------------------------------------------
static void vmx_handle_intercept_cr4access_ug(VCPU *vcpu, struct regs *r, u64 gpr, u64 tofrom){
  if(tofrom == VMX_CRX_ACCESS_TO){
	u64 cr4_proposed_value;
	
	cr4_proposed_value = *((u64 *)_vmx_decode_reg(gpr, vcpu, r));
	
	printf("\nCPU(0x%02x): CS:EIP=0x%04x:0x%08x MOV CR4, xx", vcpu->id,
		(u16)vcpu->vmcs.guest_CS_selector, (u64)vcpu->vmcs.guest_RIP);
  
	printf("\nMOV TO CR4 (flush TLB?), current=0x%08x, proposed=0x%08x",
			(u64)vcpu->vmcs.guest_CR4, cr4_proposed_value);

	#if defined (__NESTED_PAGING__)
	//we need to flush EPT mappings as we emulated CR4 load above
	__vmx_invvpid(VMX_INVVPID_SINGLECONTEXT, 1, 0);
	#endif
  }

}

//---XSETBV intercept handler-------------------------------------------
static void _vmx_handle_intercept_xsetbv(VCPU *vcpu, struct regs *r){
	u64 xcr_value;
	
	xcr_value = ((u64)r->rdx << 32) + (u64)r->rax;
	
	if(r->rcx != XCR_XFEATURE_ENABLED_MASK){
			printf("\n%s: unhandled XCR register %u", __FUNCTION__, r->rcx);
			HALT();
	}

	//XXX: TODO: check for invalid states and inject GP accordingly
	
	printf("\n%s: xcr_value=%llx", __FUNCTION__, xcr_value);
	
	//XXX: debug: dump CR4 contents
	{
		u64 t_cr4;
		t_cr4 = read_cr4();
		printf("\n%s: host cr4 value=%08x", __FUNCTION__, t_cr4);
	}
	
	//set XCR with supplied value
	xsetbv(XCR_XFEATURE_ENABLED_MASK, xcr_value);

	//skip the emulated XSETBV instruction
	vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;
}						
			


//---hvm_intercept_handler------------------------------------------------------
u64 xmhf_parteventhub_arch_x86vmx_intercept_handler(VCPU *vcpu, struct regs *r){
	//read VMCS from physical CPU/core
#ifndef __XMHF_VERIFICATION__
	xmhf_baseplatform_arch_x86vmx_getVMCS(vcpu);
#endif //__XMHF_VERIFICATION__
	//sanity check for VM-entry errors
	if( (u64)vcpu->vmcs.info_vmexit_reason & 0x80000000UL ){
		printf("\nVM-ENTRY error: reason=0x%08x, qualification=0x%016llx", 
			(u64)vcpu->vmcs.info_vmexit_reason, (u64)vcpu->vmcs.info_exit_qualification);
		xmhf_baseplatform_arch_x86vmx_dumpVMCS(vcpu);
		HALT();
	}
  
	//handle intercepts
	switch((u64)vcpu->vmcs.info_vmexit_reason){
		//--------------------------------------------------------------
		//xmhf-core and hypapp intercepts
		//--------------------------------------------------------------
		
		case VMX_VMEXIT_VMCALL:{
			//if INT 15h E820 hypercall, then let the xmhf-core handle it
			if(vcpu->vmcs.guest_CS_base == (VMX_UG_E820HOOK_CS << 4) &&
				vcpu->vmcs.guest_RIP == VMX_UG_E820HOOK_IP){
				//we need to be either in real-mode or in protected
				//mode with paging and EFLAGS.VM bit set (virtual-8086 mode)
				HALT_ON_ERRORCOND( !(vcpu->vmcs.guest_CR0 & CR0_PE)  ||
					( (vcpu->vmcs.guest_CR0 & CR0_PE) && (vcpu->vmcs.guest_CR0 & CR0_PG) &&
						(vcpu->vmcs.guest_RFLAGS & EFLAGS_VM)  ) );
				_vmx_int15_handleintercept(vcpu, r);	
			}else{	//if not E820 hook, give hypapp a chance to handle the hypercall
				//xmhf_smpguest_arch_x86vmx_quiesce(vcpu);
				if( xmhf_app_handlehypercall(vcpu, r) != APP_SUCCESS){
					printf("\nCPU(0x%02x): error(halt), unhandled hypercall 0x%08x!", vcpu->id, r->rax);
					HALT();
				}
				//xmhf_smpguest_arch_x86vmx_endquiesce(vcpu);
				vcpu->vmcs.guest_RIP += 3;
			}
		}
		break;

		case VMX_VMEXIT_IOIO:{
			_vmx_handle_intercept_ioportaccess(vcpu, r);
		}
		break;

		case VMX_VMEXIT_EPT_VIOLATION:{
			_vmx_handle_intercept_eptviolation(vcpu, r);
		}
		break;  

		case VMX_VMEXIT_INIT:{
			printf("\n***** VMEXIT_INIT xmhf_app_handleshutdown\n");
			xmhf_app_handleshutdown(vcpu, r);      
			printf("\nCPU(0x%02x): Fatal, xmhf_app_handleshutdown returned. Halting!", vcpu->id);
			HALT();
		}
		break;

		//--------------------------------------------------------------
		//xmhf-core only intercepts
		//--------------------------------------------------------------
		case VMX_VMEXIT_HLT:
			if(!vcpu->vmx_guest_unrestricted){
				printf("\nCPU(0x%02x): V86 monitor based real-mode exec. unsupported!", vcpu->id);
				HALT();
			}else{
				printf("\nCPU(0x%02x): Unexpected HLT intercept in UG, Halting!", vcpu->id);
				HALT();
			}
		break;

 		case VMX_VMEXIT_EXCEPTION:{
			switch( ((u64)vcpu->vmcs.info_vmexit_interrupt_information & INTR_INFO_VECTOR_MASK) ){
				case 0x01:
					xmhf_smpguest_arch_x86_eventhandler_dbexception(vcpu, r);
					break;				
				
				case 0x02:	//NMI
					#ifndef __XMHF_VERIFICATION__
					//we currently discharge quiescing via manual inspection
					xmhf_smpguest_arch_x86vmx_eventhandler_nmiexception(vcpu, r);
					#endif // __XMHF_VERIFICATION__
					break;
				
				default:
					printf("\nVMEXIT-EXCEPTION:");
					printf("\ncontrol_exception_bitmap=0x%08lx",
						(unsigned long)vcpu->vmcs.control_exception_bitmap);
					printf("\ninterruption information=0x%08lx", 
						(unsigned long)vcpu->vmcs.info_vmexit_interrupt_information);
					printf("\nerrorcode=0x%08lx", 
						(unsigned long)vcpu->vmcs.info_vmexit_interrupt_error_code);
					HALT();
			}
		}
		break;

 		case VMX_VMEXIT_CRX_ACCESS:{
			u64 tofrom, gpr, crx; 
			//printf("\nVMEXIT_CRX_ACCESS:");
			//printf("\ninstruction length: %u", info_vmexit_instruction_length);
			crx=(u64) ((u64)vcpu->vmcs.info_exit_qualification & 0x000000000000000FULL);
			gpr=
			 (u64) (((u64)vcpu->vmcs.info_exit_qualification & 0x0000000000000F00ULL) >> (u64)8);
			tofrom = 
			(u64) (((u64)vcpu->vmcs.info_exit_qualification & 0x0000000000000030ULL) >> (u64)4); 
			//printf("\ncrx=%u, gpr=%u, tofrom=%u", crx, gpr, tofrom);

			if ( ((int)gpr >=0) && ((int)gpr <= 7) ){
				switch(crx){
					case 0x0: //CR0 access
						vmx_handle_intercept_cr0access_ug(vcpu, r, gpr, tofrom);	
						break;
					
					case 0x4: //CR4 access
						if(!vcpu->vmx_guest_unrestricted){
							printf("\nHALT: v86 monitor based real-mode exec. unsupported!");
							HALT();
						}else{
							vmx_handle_intercept_cr4access_ug(vcpu, r, gpr, tofrom);	
						}
						break;
				
					default:
						printf("\nunhandled crx, halting!");
						HALT();
				}
				vcpu->vmcs.guest_RIP += vcpu->vmcs.info_vmexit_instruction_length;
			}else{
				printf("\n[%02x]%s: invalid gpr value (%u). halting!", vcpu->id,
					__FUNCTION__, gpr);
				HALT();
			}
		}
		break;	

 		case VMX_VMEXIT_RDMSR:
			_vmx_handle_intercept_rdmsr(vcpu, r);
			break;
			
		case VMX_VMEXIT_WRMSR:
			_vmx_handle_intercept_wrmsr(vcpu, r);
			break;
			
		case VMX_VMEXIT_CPUID:
			_vmx_handle_intercept_cpuid(vcpu, r);
			break;

		case VMX_VMEXIT_TASKSWITCH:{
			u64 idt_v = vcpu->vmcs.info_IDT_vectoring_information & VECTORING_INFO_VALID_MASK;
			u64 type = vcpu->vmcs.info_IDT_vectoring_information & VECTORING_INFO_TYPE_MASK;
			u64 reason = vcpu->vmcs.info_exit_qualification >> 30;
			u16 tss_selector = (u16)vcpu->vmcs.info_exit_qualification;
			
			if(reason == TASK_SWITCH_GATE && type == INTR_TYPE_NMI){
				printf("\nCPU(0x%02x): NMI received (MP guest shutdown?)", vcpu->id);
					xmhf_app_handleshutdown(vcpu, r);      
				printf("\nCPU(0x%02x): warning, xmhf_app_handleshutdown returned!", vcpu->id);
				printf("\nCPU(0x%02x): HALTING!", vcpu->id);
				HALT();
			}else{
				printf("\nCPU(0x%02x): Unhandled Task Switch. Halt!", vcpu->id);
				printf("\n	idt_v=0x%08x, type=0x%08x, reason=0x%08x, tsssel=0x%04x",
					idt_v, type, reason, tss_selector); 
			}
			HALT();
		}
		break;

		case VMX_VMEXIT_XSETBV:{
			_vmx_handle_intercept_xsetbv(vcpu, r);
		}
		break;

    
		default:{
			printf("\nCPU(0x%02x): Unhandled intercept: 0x%08x", vcpu->id, (u64)vcpu->vmcs.info_vmexit_reason);
			printf("\n	CPU(0x%02x): EFLAGS=0x%08x", vcpu->id, (u64)vcpu->vmcs.guest_RFLAGS);
			printf("\n	SS:ESP =0x%04x:0x%08x", (u16)vcpu->vmcs.guest_SS_selector, (u64)vcpu->vmcs.guest_RSP);
			printf("\n	CS:EIP =0x%04x:0x%08x", (u16)vcpu->vmcs.guest_CS_selector, (u64)vcpu->vmcs.guest_RIP);
			printf("\n	IDTR base:limit=0x%08x:0x%04x", (u64)vcpu->vmcs.guest_IDTR_base,
					(u16)vcpu->vmcs.guest_IDTR_limit);
			printf("\n	GDTR base:limit=0x%08x:0x%04x", (u64)vcpu->vmcs.guest_GDTR_base,
					(u16)vcpu->vmcs.guest_GDTR_limit);
			if(vcpu->vmcs.info_IDT_vectoring_information & 0x80000000){
				printf("\nCPU(0x%02x): HALT; Nested events unhandled 0x%08x",
					vcpu->id, vcpu->vmcs.info_IDT_vectoring_information);
			}
			HALT();
		}		
	} //end switch((u64)vcpu->vmcs.info_vmexit_reason)
	

 	//check and clear guest interruptibility state
	if(vcpu->vmcs.guest_interruptibility != 0){
		vcpu->vmcs.guest_interruptibility = 0;
	}

	//make sure we have no nested events
	if(vcpu->vmcs.info_IDT_vectoring_information & 0x80000000){
		printf("\nCPU(0x%02x): HALT; Nested events unhandled with hwp:0x%08x",
			vcpu->id, vcpu->vmcs.info_IDT_vectoring_information);
		HALT();
	}

	//write updated VMCS back to CPU
#ifndef __XMHF_VERIFICATION__
	xmhf_baseplatform_arch_x86vmx_putVMCS(vcpu);
#endif // __XMHF_VERIFICATION__


#ifdef __XMHF_VERIFICATION_DRIVEASSERTS__
	//ensure that whenever a partition is resumed on a vcpu, we have extended paging
	//enabled and that the base points to the extended page tables we have initialized
	assert( (vcpu->vmcs.control_VMX_seccpu_based & 0x2) );
	assert( (vcpu->vmcs.control_EPT_pointer_high == 0) && (vcpu->vmcs.control_EPT_pointer_full == (hva2spa((void*)vcpu->vmx_vaddr_ept_pml4_table) | 0x1E)) );
#endif	

	return 1;
}
