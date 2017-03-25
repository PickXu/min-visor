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

//vmx_eap.h - VMX VT-d (External Access Protection) declarations/definitions
//author: amit vasudevan (amitvasudevan@acm.org)

#ifndef __VMX_EAP_H__
#define __VMX_EAP_H__

#define VTD_DMAR_SIGNATURE  (0x52414D44) //"DMAR"
#define VTD_MAX_DRHD   8		//maximum number of DMAR h/w units   

//VT-d register offsets (sec. 10.4, Intel_VT_for_Direct_IO)
#define VTD_VER_REG_OFF 		0x000				//arch. version (32-bit)
#define VTD_CAP_REG_OFF 		0x008				//h/w capabilities (64-bit)				
#define VTD_ECAP_REG_OFF  	0x010				//h/w extended capabilities (64-bit)
#define VTD_GCMD_REG_OFF  	0x018				//global command (32-bit)
#define VTD_GSTS_REG_OFF  	0x01C				//global status (32-bit)
#define VTD_RTADDR_REG_OFF  0x020				//root-entry table address (64-bit)
#define VTD_CCMD_REG_OFF  	0x028				//manage context-entry cache (64-bit) 
#define VTD_FSTS_REG_OFF  	0x034				//report fault/error status (32-bit)
#define VTD_FECTL_REG_OFF 	0x038				//interrupt control (32-bit)
#define VTD_PMEN_REG_OFF  	0x064				//enable DMA protected memory regions (32-bits)
#define VTD_IVA_REG_OFF  		0x0DEAD  		//invalidate address register (64-bits)
																				//note: the offset of this register is computed
                                    		//at runtime for a specified DMAR device
#define VTD_IOTLB_REG_OFF   0x0BEEF     //IOTLB invalidate register (64-bits)
																				//note: the offset is VTD_IVA_REG_OFF + 8 and
																				//computed at runtime for a specified DMAR device


//VT-d register access types (custom definitions)
#define VTD_REG_READ  			0xaa				//read VTD register
#define VTD_REG_WRITE 			0xbb				//write VTD register

//Vt-d register access widths (custom definitions)
#define VTD_REG_32BITS  		0x32ff
#define VTD_REG_64BITS  		0x64ff

//Vt-d page-table bits
#define VTD_READ						0x1
#define VTD_WRITE						0x2
#define VTD_SUPERPAGE				(0x1UL << 7)


#ifndef __ASSEMBLY__

//Vt-d DMAR structure
typedef struct{
  u64 signature;
  u64 length;
  u8 revision;
  u8 checksum;
  u8 oemid[6];
  u64 oemtableid;
	u64 oemrevision;
	u64 creatorid;
	u64 creatorrevision;
  u8 hostaddresswidth;
  u8 flags;
  u8 rsvdz[10];    
}__attribute__ ((packed)) VTD_DMAR;

//VT-d DRHD structure
typedef struct{
  u16 type;
  u16 length;
  u8 flags;
  u8 rsvdz0;
  u16 pcisegment;
  u64 regbaseaddr;
}__attribute__ ((packed)) VTD_DRHD;


//------------------------------------------------------------------------------
//VT-d register structure definitions

//VTD_VER_REG (sec. 10.4.1)
typedef union {
  u64 value;
  struct
  {
    u64 min : 4;			//minor version no.
    u64 max : 4;			//major version no.
    u64 rsvdz : 24;		//reserved
  } bits;
} __attribute__ ((packed)) VTD_VER_REG;

//VTD_CAP_REG (sec. 10.4.2)
typedef union {
  u64 value;
  struct
  {
    u64 nd : 3;    		//no. of domains
    u64 afl : 1;			//advanced fault logging
    u64 rwbf : 1;			//required write-buffer flushing
    u64 plmr : 1;			//protected low-memory region
    u64 phmr : 1;			//protected high-memory region
    u64 cm : 1;				//caching mode
    u64 sagaw: 5;			//supported adjuested guest address widths
    u64 rsvdz0: 3;		//reserved
    u64 mgaw : 6;			//maximum guest address width
    u64 zlr: 1;				//zero length read
    u64 isoch: 1;			//isochrony
    u64 fro : 10;			//fault-recording register offset
    u64 sps : 4;			//super-page support
    u64 rsvdz1: 1;		//reserved
    u64 psi: 1;				//page selective invalidation
    u64 nfr: 8;				//no. of fault-recording registers
    u64 mamv: 6;			//max. address mask value
    u64 dwd: 1;				//DMA write draining
    u64 drd: 1;				//DMA read draining
    u64 rsvdz2: 8;		//reserved
  } bits;
} __attribute__ ((packed)) VTD_CAP_REG;

//VTD_ECAP_REG (sec. 10.4.3)
typedef union {
  u64 value;
  struct
  {
    u64 c:1;					//coherency
    u64 qi:1;					//queued invalidation support
    u64 di:1;					//device IOTLB support
    u64 ir:1;					//interrupt remapping support
    u64 eim:1;				//extended interrupt mode
    u64 ch:1;					//caching hints
    u64 pt:1;					//pass through 
    u64 sc:1;					//snoop control
    u64 iro:10;				//IOTLB register offset
    u64 rsvdz0: 2;		//reserved
    u64 mhmv: 4;			//maximum handle mask value
    u64 rsvdz1: 40;		//reserved
  } bits;
} __attribute__ ((packed)) VTD_ECAP_REG;

//VTD_GCMD_REG (sec. 10.4.4)
typedef union {
  u64 value;
  struct
  {
    u64 rsvdz0: 23;		//reserved
    u64 cfi: 1;				//compatibility format interrupt
    u64 sirtp: 1;			//set interrupt remap table pointer
    u64 ire:1;				//interrupt remapping enable
    u64 qie:1;				//queued invalidation enable
    u64 wbf:1;				//write buffer flush
    u64 eafl:1;				//enable advanced fault logging
    u64 sfl:1;				//set fault log
    u64 srtp:1;				//set root table pointer
    u64 te:1;					//translation enable
  } bits;
} __attribute__ ((packed)) VTD_GCMD_REG;

//VTD_GSTS_REG (sec. 10.4.5)
typedef union {
  u64 value;
  struct
  {
    u64 rsvdz0: 23;		//reserved
    u64 cfis:1;				//compatibility interrupt format status
    u64 irtps:1;			//interrupt remapping table pointer status
    u64 ires:1;				//interrupt remapping enable status
    u64 qies:1;				//queued invalidation enable status
    u64 wbfs:1;				//write buffer flush status
    u64 afls:1;				//advanced fault logging status
    u64 fls:1;				//fault log status
    u64 rtps:1;				//root table pointer status
    u64 tes:1;				//translation enable status 
  } bits;
} __attribute__ ((packed)) VTD_GSTS_REG;

//VTD_RTADDR_REG (sec. 10.4.6)
typedef union {
  u64 value;
  struct
  {
    u64 rsvdz0: 12;		//reserved
    u64 rta: 52;			//root table address
  } bits;
} __attribute__ ((packed)) VTD_RTADDR_REG;

//VTD_CCMD_REG (sec. 10.4.7)
typedef union {
  u64 value;
  struct
  {
    u64 did:16;				//domain id
    u64 sid:16;				//source id
    u64 fm:2;					//function mask
    u64 rsvdz0: 25;		//reserved
    u64 caig:2;				//context invalidation actual granularity
    u64 cirg:2;				//context invalidation request granularity
    u64 icc:1;				//invalidate context-cache 
  } bits;
} __attribute__ ((packed)) VTD_CCMD_REG;

//VTD_IOTLB_REG (sec. 10.4.8.1)
typedef union {
  u64 value;
  struct
  {
    u64 rsvdz0: 32;		//reserved
    u64 did:16;				//domain-id
    u64 dw: 1;				//drain writes
    u64 dr:1;					//drain reads
    u64 rsvdz1: 7;		//reserved
    u64 iaig: 3;			//IOTLB actual invalidation granularity
    u64 iirg: 3;			//IOTLB request invalidation granularity
    u64 ivt: 1;				//invalidate IOTLB 
  } bits;
} __attribute__ ((packed)) VTD_IOTLB_REG;

//VTD_IVA_REG (sec. 10.4.8.2)
typedef union {
  u64 value;
  struct
  {
    u64 am: 6;				//address mask
    u64 ih:1;					//invalidation hint
    u64 rsvdz0: 5;		//reserved
    u64 addr:52;			//address
  } bits;
} __attribute__ ((packed)) VTD_IVA_REG;


//VTD_FSTS_REG	(sec. 10.4.9)
typedef union {
  u64 value;
  struct
  {
    u64 pfo:1;				//fault overflow
    u64 ppf:1;				//primary pending fault
    u64 afo:1;				//advanced fault overflow
    u64 apf:1;				//advanced pending fault
    u64 iqe:1;				//invalidation queue error				
    u64 ice:1;				//invalidation completion error
    u64 ite:1;				//invalidation time-out error
    u64 rsvdz0: 1;		//reserved
    u64 fri:8;				//fault record index
    u64 rsvdz1: 16;		//reserved
  } bits;
} __attribute__ ((packed)) VTD_FSTS_REG;

//VTD_FECTL_REG	(sec. 10.4.10)
typedef union {
  u64 value;
  struct
  {
    u64 rsvdp0:30;		//reserved
    u64 ip:1;					//interrupt pending
    u64 im:1;					//interrupt mask
  } bits;
} __attribute__ ((packed)) VTD_FECTL_REG;

//VTD_PMEN_REG (sec. 10.4.16)
typedef union {
  u64 value;
  struct
  {
    u64 prs:1;			//protected region status
    u64 rsvdp:30;		//reserved
    u64 epm:1;			//enable protected memory
  } bits;
} __attribute__ ((packed)) VTD_PMEN_REG;

		
#endif //__ASSEMBLY__

#endif //__VMX_EAP_H__
