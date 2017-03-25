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

/*
 */

/**
 * appmain.c
 * Primary TrustVisor entry point from the EMHF core
 * authors: amit vasudevan (amitvasudevan@acm.org)
 * jnewsome@cmu.edu, jonmccune@cmu.edu
 */

#include <xmhf.h> 
#include <trustvisor.h>
//#include <malloc.h>
//#include <scode.h>
//#include <hc_utpm.h>
#include <nv.h>

#include <tv_log.h>
#include <tv_emhf.h>
#include <cmdline.h>
#include <hpt.h>
#include <hptw.h>
#include <hptw_emhf.h>

//#define IA32_PQR_ASSOC 0x0c8f
//#define IA32_L3_MASK_0 0x0c90
//#define CAT_ENABLED

volatile u64 occupied;

const cmdline_option_t gc_trustvisor_available_cmdline_options[] = {
  { "nvpalpcr0", "0000000000000000000000000000000000000000"}, /* Req'd PCR[0] of NvMuxPal */
  { "nvenforce", "true" }, /* true|false - actually enforce nvpalpcr0? */
  { NULL, NULL }
};

/*
bool cmdline_get_nvenforce(char param_vals[][MAX_VALUE_LEN]) {
    const char *nvenforce = cmdline_get_option_val(gc_trustvisor_available_cmdline_options,
                                                   param_vals,
                                                   "nvenforce");
    if ( nvenforce == NULL || *nvenforce == '\0' )
        return true; // drsired default behavior is YES, DO ENFORCE 

    if ( strncmp(nvenforce, "false", 6 ) == 0 )
        return false;

    return true;
}
*/

/* lazy translation table to go from ascii hex to binary, one nibble
 * at a time */
const uint8_t gc_asc2nib[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0,
    0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12,
    13, 14, 15 }; /* don't bother going past 'f' */
#define ASC2NIB(x) ((x) < 103 ? gc_asc2nib[x] : 0)

/* allow caller to query whether param exists on cmdline by invoking
 * with NULL reqd_pcr0 */
/*
bool cmdline_get_nvpalpcr0(char param_vals[][MAX_VALUE_LEN], // in 
                           uint8_t *reqd_pcr0) {   // out 
    int i;
    const char *ascii = cmdline_get_option_val(gc_trustvisor_available_cmdline_options,
                                               param_vals,
                                               "nvpalpcr0");
    if ( ascii == NULL || *ascii == '\0' )
        return false; // no param found 

    if ( reqd_pcr0 == NULL )
        return true;

    for(i=0; i<20; i++)
        reqd_pcr0[i] = (ASC2NIB((uint8_t)ascii[2*i]) << 4) | ASC2NIB((uint8_t)ascii[2*i+1]);

    return true;
}
*/

void parse_boot_cmdline(const char *cmdline) {
  char param_vals[ARRAY_SIZE(gc_trustvisor_available_cmdline_options)][MAX_VALUE_LEN];

  cmdline_parse(cmdline, gc_trustvisor_available_cmdline_options, param_vals);
  /*
  g_nvenforce = cmdline_get_nvenforce(param_vals);
  if(!cmdline_get_nvpalpcr0(param_vals, g_nvpalpcr0) && g_nvenforce) {
    // Emit warning that enforcing uPCR[0] for NV access doesn't make
    // sense without specifying which PAL _should_ have access
    eu_warn("WARNING: NV enforcement ENABLED, but NVPAL's uPCR[0] UNSPECIFIED!");
  }

  eu_trace("NV Enforcement %s", g_nvenforce ? "ENABLED" : "DISABLED");
  print_hex("NV uPCR[0] required to be: ", g_nvpalpcr0, sizeof(g_nvpalpcr0));
  */
}

/**
 * This is the primary entry-point from the EMHF Core during
 * hypervisor initialization.
 */
u64 tv_app_main(VCPU *vcpu, APP_PARAM_BLOCK *apb){
  HALT_ON_ERRORCOND(NULL != vcpu);
  HALT_ON_ERRORCOND(NULL != apb);

  eu_trace("CPU(0x%02x)", vcpu->id);

  if (vcpu->isbsp) {
    eu_trace("CPU(0x%02x): init\n", vcpu->id);

    eu_trace("CPU(0x%02x) apb->cmdline: \"%s\"", vcpu->id, apb->cmdline);
    parse_boot_cmdline(apb->cmdline);

#ifdef __PAL__
    init_scode(vcpu);
#endif
  }

  /* force these to be linked in */
  emhfc_log_error("");

  return APP_INIT_SUCCESS;  //successful
}

struct inbuf_s {
  u64 gva;
  u64 len;
};
struct outbuf_s {
  u64 gva;
  u64 len_gva;
};


#ifdef __PAL__
static u64 do_TV_HC_SHARE(VCPU *vcpu, struct regs *r)
{
  u64 scode_entry, addrs_gva, lens_gva, count;
  u64 *addrs=NULL, *lens=NULL;
  u64 ret = 1;

  scode_entry = r->rcx;

  addrs_gva = r->rdx;
  lens_gva = r->rsi;
  count = r->rdi;

  EU_CHK( addrs = malloc(count * sizeof(addrs[0])));
  EU_CHK( lens = malloc(count * sizeof(lens[0])));

  EU_CHKN( copy_from_current_guest( vcpu,
                                    addrs,
                                    addrs_gva,
                                    sizeof(addrs[0])*count));
  EU_CHKN( copy_from_current_guest( vcpu,
                                    lens,
                                    lens_gva,
                                    sizeof(lens[0])*count));

  ret = scode_share_ranges(vcpu, scode_entry, addrs, lens, count);

 out:
  free(addrs);
  free(lens);
  return ret;
}
#endif

static u64 do_TV_HC_TEST(VCPU *vcpu, struct regs *r)
{
  (void)r;
  eu_trace("CPU(0x%02x): test hypercall", vcpu->id);
  return 0;
}

#ifdef __PAL__
static u64 do_TV_HC_REG(VCPU *vcpu, struct regs *r)
{
  u64 scode_info,  scode_pm, scode_en;
  u64 ret;
  
  scode_info = r->rcx; // sensitive code as guest virtual address 
  scode_pm = r->rsi; // sensitive code params information address 
  scode_en = r->rdi; // sensitive code entry point in rdi 

  // do atomic scode registration 
  ret = scode_register(vcpu, scode_info, scode_pm, scode_en);

  return ret;
}

static u64 do_TV_HC_UNREG(VCPU *vcpu, struct regs *r)
{
  u64 scode_gva;
  u64 ret;
  // sensitive code as guest virtual address in rcx 
  scode_gva = r->rcx;

  // do atomic scode unregistration 
  ret = scode_unregister(vcpu, scode_gva);

  return ret;
}
#endif

//XUM
#ifdef CAT_ENABLED
static u64 do_TV_HC_CAT_INIT(VCPU *vcpu, struct regs *r) {
  //configure CBMs for all CLOSes
  //CLOS[0-14] occupy 0-6MB, CLOS[15] occupies 6-8MB
  uint64_t i;
  uint64_t msr_val=0;
  printf("\nCPU%02x: CAT INIT(%d) handler...",vcpu->id, r->rax); 
  for(i=0;i<15;i++){
    asm volatile("rdmsr\n"
		:"=A"(msr_val)
		: "c"(IA32_L3_MASK_0+i)
		);
    msr_val = ((msr_val|0xfffff)&0xfffffffffffffff0);
    asm volatile("wrmsr\n"
	 	: : "A" (msr_val),"c"(IA32_L3_MASK_0+i)
		);
  }

  asm volatile("rdmsr\n"
                : "=A"(msr_val)
		: "c"(IA32_L3_MASK_0+15)
                );
  msr_val = (msr_val&0xfffffffffff0000f);
    asm volatile("wrmsr\n"
                : : "A" (msr_val),"c"(IA32_L3_MASK_0+15)
		);
  return 0;
}
#endif

static u64 do_TV_HC_VCPU_LOCK(VCPU *vcpu, struct regs *r)
{
  uint64_t msr_val=0;
  uint64_t rcx=0;
  uint16_t port;
  uint8_t val;

  //uint64_t cur,rest,len;
  //void* addr;
  //u64 j,k,i;
  //hc_args args;
  //hptw_emhf_checked_guest_ctx_t ctx;
  //uint64_t cycles_high,cycles_low,cycles_high1,cycles_low1;
  //uint64_t total_time=0;
  //printf("\nCPU%02x: VCPU_LOCK(%d) handler: HC_ARGS at %p\n",vcpu->id, r->rax,(void*)r->rbx); 
  
  /* Disable IF and TF */
  //vcpu->vmcs.guest_RFLAGS &= 0xfffffffffffffcff;
  while(occupied);
  occupied = 1;
  r=r;

  /* Disable IF only */
  vcpu->vmcs.guest_RFLAGS &= 0xfffffffffffffdff;

  /* Disable NMI */
  port = 0x70;
  asm volatile("inb %1,%0\n"
		: "=a" (val)
		: "Nd" (port)
		);
  val = val | 0x80;
  asm volatile("outb %0, %1\n"
	 	: : "a" (val), "Nd" (port)); 
  //outb(inb(0x70)|0x80,0x70); 

  /* Disable DR7 */
  

  /* Disable H/W Prefetcher */
  rcx = 0x1a4;
  asm volatile("rdmsr\n"
                        : "=A"(msr_val)
                        : "c"(rcx)
                        );
  msr_val = (msr_val|0xf);   
  asm volatile("wrmsr\n"
			: : "A"(msr_val), "c"(rcx)
			);	

#ifdef CAT_ENABLED
 	//enter CLOS[15]
	rcx = IA32_PQR_ASSOC;
	asm volatile("rdmsr\n"
			: "=A"(msr_val)
			: "c"(rcx)
			);
	msr_val = (msr_val|((uint64_t)0xf<<32));
	asm volatile("wrmsr\n"
			: : "A"(msr_val), "c"(rcx)
			);	
#endif
  /*

  hptw_emhf_checked_guest_ctx_init_of_vcpu( &ctx, vcpu);
  //Load hc_args from guest's virtual address into arg
  rest = sizeof(hc_args);
  addr = hptw_checked_access_va(&ctx.super,HPT_PROTS_R,ctx.cpl,r->rbx,rest,&len);
  memcpy(&args,addr,sizeof(hc_args));

  
  for(k=0;k<args.num;k++) {
  uint64_t start,num,usize,skip; 
  start = args.addr[k];
  num = args.no[k];
  usize = args.usize[k];
  skip = args.skip[k];
  //printf("\n%d-th region: from %p load %d entries every %d entries, each of %d bytes...\n", k, (void*)start, num, skip, usize);
    
  //cflush target data range
  //, which is defined by r->rbx and r->rcx
  for(j=0;j<num;j++){
    rest = usize;  
    cur = start+skip*j*usize; 
    while(rest) {
      asm volatile( "rdtsc\n"
                     "mov %%rdx,%0\n"
                     "mov %%rax,%1\n"
                     : "=r" (cycles_high), "=r"(cycles_low)
                     : : "%rax", "%rbx", "%rcx", "%rdx");
      addr = hptw_checked_access_va(&ctx.super,HPT_PROTS_W,ctx.cpl,cur+usize-rest,rest,&len);
      asm volatile("rdtsc\n"
                     "mov %%rdx,%0\n"
                     "mov %%rax,%1\n"
                     : "=r" (cycles_high1), "=r"(cycles_low1)
                     : : "%rax", "%rbx", "%rcx", "%rdx");
      //printf("flush region %p to %p\n", (void*)addr,(void*)addr+len);
      if (!addr) return 1;
      asm volatile("mfence\n");
      for(i=(u64)addr;i<((u64)addr+len);i+=4){
        asm volatile("clflush (%0)\n"
		     "mov (%0),%%rax\n"
		:
		: "r" ((void*)i)
		: "rax");
      }
      rest -= len;
      total_time += ((((uint64_t) cycles_high1 << 32)|cycles_low1)-(((uint64_t) cycles_high << 32)|cycles_low));
    }
  }

  }
  printf("Total translation time: %u\n",total_time);
  */
  asm volatile("wbinvd\n");

  return 0;
}

static u64 do_TV_HC_VCPU_UNLOCK(VCPU *vcpu, struct regs *r)
{

  uint16_t port;
  uint8_t val;
  //printf("\nCPU%02x: VCPU_UNLOCK(%d) handler...",vcpu->id,r->rax); 
  r=r;

#ifdef CAT_ENABLED
  uint64_t rcx=0;
  uint64_t msr_val=0;

	//TODO: cflush target data range
	
	//enter CLOS[0]
	rcx = IA32_PQR_ASSOC;
	asm volatile("rdmsr\n"
			: "=A"(msr_val)
			: "c"(rcx)
			);
	msr_val = (msr_val&0xfffffff0ffffffff);
	asm volatile("wrmsr\n"
			: : "A"(msr_val), "c"(rcx)
			);	
#endif

  /* Restore H/W Prefetcher */
  /*
  rcx = 0x1a4;
  asm volatile("rdmsr\n"
                        : "=A"(msr_val)
                        : "c"(rcx)
                        );
  msr_val = (msr_val&(0xfffffffffffffff0));   
  asm volatile("wrmsr\n"
			: : "A"(msr_val), "c"(rcx)
			);	
  */

 
  vcpu->vmcs.guest_RFLAGS |= 0x0000000000000200;
 
  /* Resume NMI */
  port = 0x70;
  asm volatile("inb %1,%0\n"
		: "=a" (val)
		: "Nd" (port)
		);
  val = val & 0x7f;
  asm volatile("outb %0, %1\n"
	 	: : "a" (val), "Nd" (port)); 
  //outb(inb(0x70)&0x7f,0x70); 

  asm volatile("wbinvd\n");


  occupied = 0;

  return 0;
}



static u64 do_TV_HC_INIT_PMC(VCPU *vcpu, struct regs *r)
{
  int rax,rcx,rdx;
  printf("\nCPU%02x(%d): Init PMC on IA32_PERFEVTSEL%d with umask:event as %04x ...", vcpu->id, r->rax, r->rbx,(0xffff&r->rcx));
  vcpu->vmcs.control_VMX_cpu_based &= ~(1<<11|1<<12);

  if ((r->rcx&0xff) == 0xa3) {
	/*
	if ((r->rcx&0xff00) != 0x0500 && (r->rcx&0xff00) != 0x0600 && (r->rcx&0xff00) != 0x0c00) {
		rax = 0x00630000 | (0xffff&r->rcx);
	} else 
	*/
	if ((r->rcx&0xff00) == 0x0c00 || (r->rcx&0xff00) == 0x0600 || (r->rcx&0xff00) == 0x0500) {
		rax = 0x00430000 | (0xffff&r->rcx) | ((0xff00&r->rcx)<<16);
	} else {
		rax = 0x00430000 | (0xffff&r->rcx);
	}
  } else {
	rax = 0x00430000 | (0xffff&r->rcx);
  }
  rcx = 0x186+r->rbx;
  // Select the LLC Misses Event
  asm volatile(	"xor %%rdx,%%rdx\n"
		"wrmsr\n"
		:
		: "a" (rax), "c" (rcx)); 

  // Enable corrrsponding PMC in IA32_PERF_GLOBAL_CTRL MSR
  rcx = 0x38f;
  asm volatile("rdmsr\n"
	       : "=a" (rax), "=d" (rdx)
	       : "c" (rcx)
		);
  rax = rax | (1<<r->rbx);
  asm volatile( "xor %%rdx,%%rdx\n"
                "wrmsr\n"
                :
                : "a" (rax), "c" (rcx));

   // Configure Offcore
   if ((r->rcx&0xffff) == 0x01b7 || (r->rcx&0xffff) == 0x01bb) { 
	rax = 0x84000000 | (r->rbx?4:1);
	rcx = 0x1a6+r->rbx;
	printf("Configure offcore events: %04x\n",(r->rcx&0xffff));
	asm volatile("xor %%rdx,%%rdx\n"
		"wrmsr\n"
		:
		: "a" (rax), "c" (rcx)); 
   }


   printf("Guest CR3: 0x%x, Host CR3: 0x%x\n", vcpu->vmcs.guest_CR3, vcpu->vmcs.host_CR3);

  return 0;
}

static u64 do_TV_HC_RDPMC(VCPU *vcpu, struct regs *r)
{
  int rax, rdx;
  printf("\nCPU%02x(%d): IA32_PMC at %08x...", vcpu->id, r->rax, r->rcx);
  asm volatile("rdmsr\n"
		: "=a" (rax), "=d" (rdx)
		: "c" (r->rcx)
		);
  printf("%08x:%08x", rdx,rax);
  
  return 0;
}

static u64 do_TV_HC_RUN(VCPU *vcpu, struct regs *r) 
{
  uint8_t data[32768];
  int rcx, rax1, rdx1, rax2, rdx2, rax3, rdx3, rax4, rdx4;
  int i;
  printf("\nCPU%02x(%d): Iterate over array of 32KB once...", vcpu->id, r->rax);

  for(i=0;i<32768;i++)
    data[i] = data[i]; 
   
  rcx = 0x0c1;
  asm volatile("rdmsr\n"
		: "=a" (rax1), "=d" (rdx1)
		: "c" (rcx)
		);
  rcx = 0x0c2;
  asm volatile("rdmsr\n"
		: "=a" (rax2), "=d" (rdx2)
		: "c" (rcx)
		);

  for(i=0;i<32768;i++)
    data[i] = data[i]; 

  rcx = 0x0c1;
  asm volatile("rdmsr\n"
		: "=a" (rax3), "=d" (rdx3)
		: "c" (rcx)
		);
  rcx = 0x0c2;
  asm volatile("rdmsr\n"
		: "=a" (rax4), "=d" (rdx4)
		: "c" (rcx)
		);


  printf("\n%08x:%08x",rax1,rdx1);
  printf("\n%08x:%08x",rax2,rdx2);
  printf("\n%08x:%08x",rax3,rdx3);
  printf("\n%08x:%08x",rax4,rdx4);

  return 0;
}

#ifdef __UTPM__
static u64 do_TV_HC_UTPM_SEAL_DEPRECATED(VCPU *vcpu, struct regs *r)
{
  struct inbuf_s plainbuf_s;
  struct outbuf_s sealedbuf_s;
  gva_t plainbuf_s_gva;
  gva_t sealedbuf_s_gva;
  gva_t pcr_gva;
  u64 ret = 1;

  plainbuf_s_gva = r->rcx;
  sealedbuf_s_gva = r->rsi;
  pcr_gva = r->rdx;        
        
  EU_CHKN( copy_from_current_guest( vcpu,
                                    &plainbuf_s,
                                    plainbuf_s_gva,
                                    sizeof(plainbuf_s)));

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sealedbuf_s,
                                    sealedbuf_s_gva,
                                    sizeof(sealedbuf_s)));

  ret = hc_utpm_seal_deprecated(vcpu,
                                plainbuf_s.gva, plainbuf_s.len,
                                pcr_gva,
                                sealedbuf_s.gva, sealedbuf_s.len_gva);

 out:
  return ret;
}

static u64 do_TV_HC_UTPM_UNSEAL(VCPU *vcpu, struct regs *r)
{
  struct inbuf_s sealedbuf_s;
  struct outbuf_s plainbuf_s;
  gva_t sealedbuf_s_gva, plainbuf_s_gva;
  gva_t digestAtCreation_gva;
  u64 ret = 1;

  sealedbuf_s_gva = r->rcx;
  plainbuf_s_gva = r->rdx;
  digestAtCreation_gva = r->rsi;				

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sealedbuf_s,
                                    sealedbuf_s_gva,
                                    sizeof(sealedbuf_s)));
  EU_CHKN( copy_from_current_guest( vcpu,
                                    &plainbuf_s,
                                    plainbuf_s_gva,
                                    sizeof(plainbuf_s)));
				
  ret = hc_utpm_unseal( vcpu,
                        sealedbuf_s.gva, sealedbuf_s.len,
                        plainbuf_s.gva, plainbuf_s.len_gva,
                        digestAtCreation_gva);

 out:
  return ret;
}

static u64 do_TV_HC_UTPM_SEAL(VCPU *vcpu, struct regs *r)
{
  struct inbuf_s plainbuf_s;
  struct outbuf_s sealedbuf_s;
  gva_t sealedbuf_s_gva, plainbuf_s_gva;
  gva_t pcrinfo_gva;
  u64 ret=1;
        
  plainbuf_s_gva = r->rcx;
  sealedbuf_s_gva = r->rsi;
  pcrinfo_gva = r->rdx;

  ret = 1;
  EU_CHKN( copy_from_current_guest( vcpu,
                                    &plainbuf_s,
                                    plainbuf_s_gva,
                                    sizeof(plainbuf_s)));
  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sealedbuf_s,
                                    sealedbuf_s_gva,
                                    sizeof(sealedbuf_s)));

  ret = hc_utpm_seal( vcpu,
                      plainbuf_s.gva, plainbuf_s.len,
                      pcrinfo_gva,
                      sealedbuf_s.gva, sealedbuf_s.len_gva);
 out:
  return ret;
}

static u64 do_TV_HC_UTPM_UNSEAL_DEPRECATED(VCPU *vcpu, struct regs *r)
{
  struct inbuf_s sealedbuf_s;
  struct outbuf_s plainbuf_s;
  gva_t plainbuf_s_gva, sealedbuf_s_gva;
  u64 ret=1;

  sealedbuf_s_gva = r->rcx;
  plainbuf_s_gva = r->rdx;

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sealedbuf_s,
                                    sealedbuf_s_gva,
                                    sizeof(sealedbuf_s)));

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &plainbuf_s,
                                    plainbuf_s_gva,
                                    sizeof(plainbuf_s)));

  ret = hc_utpm_unseal_deprecated(vcpu,
                                  sealedbuf_s.gva, sealedbuf_s.len,
                                  plainbuf_s.gva, plainbuf_s.len_gva);

 out:
  return ret;
}

static u64 do_TV_HC_UTPM_QUOTE(VCPU *vcpu, struct regs *r)
{
  gva_t nonce_gva, tpmsel_gva;
  struct outbuf_s sigbuf_s;
  gva_t sigbuf_s_gva;
  struct outbuf_s pcr_comp_buf_s;
  gva_t pcr_comp_buf_s_gva;
  u64 ret = 1;

  eu_trace("TV_HC_UTPM_QUOTE hypercall received.");
        
  nonce_gva = r->rsi; // address of nonce to be sealed 
  tpmsel_gva = r->rcx; // tpm selection data address 
  pcr_comp_buf_s_gva = r->rdi; // PCR Composite buffer and its length 
  sigbuf_s_gva = r->rdx; // signature buffer and its length 

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sigbuf_s,
                                    sigbuf_s_gva,
                                    sizeof(sigbuf_s)));
        
  EU_CHKN( copy_from_current_guest( vcpu,
                                    &pcr_comp_buf_s,
                                    pcr_comp_buf_s_gva,
                                    sizeof(sigbuf_s)));
				
  ret = hc_utpm_quote( vcpu,
                       nonce_gva,
                       tpmsel_gva,
                       sigbuf_s.gva, sigbuf_s.len_gva,
                       pcr_comp_buf_s.gva, pcr_comp_buf_s.len_gva);

 out:
  return ret;
}

static u64 do_TV_HC_UTPM_ID_GETPUB(VCPU *vcpu, struct regs *r)
{
  u64 dst_gva;
  u64 dst_sz_gva;
  u64 ret;

  dst_gva = r->rcx;
  dst_sz_gva = r->rdx;
  ret = hc_utpm_utpm_id_getpub( vcpu, dst_gva, dst_sz_gva);

  return ret;
}

static u64 do_TV_HC_UTPM_QUOTE_DEPRECATED(VCPU *vcpu, struct regs *r)
{
  struct outbuf_s sigbuf_s;
  gva_t sigbuf_s_gva;
  gva_t nonce_gva, tpmsel_gva;
  u64 ret = 1;

  nonce_gva = r->rsi; // address of nonce to be sealed 
  tpmsel_gva = r->rcx; // tpm selection data address 
  sigbuf_s_gva = r->rdx;

  EU_CHKN( copy_from_current_guest( vcpu,
                                    &sigbuf_s,
                                    sigbuf_s_gva,
                                    sizeof(sigbuf_s)));

  ret = hc_utpm_quote_deprecated( vcpu,
                                  nonce_gva,
                                  tpmsel_gva,
                                  sigbuf_s.gva, sigbuf_s.len_gva);

 out:
  return ret;
}

static u64 do_TV_HC_UTPM_PCRREAD(VCPU *vcpu, struct regs *r)
{
  u64 addr, num;
  u64 ret=1;

  addr = r->rdx;
  num = r->rcx;

  ret = hc_utpm_pcrread(vcpu, addr, num);

  return ret;
}

static u64 do_TV_HC_UTPM_PCREXT(VCPU *vcpu, struct regs *r)
{
  u64 meas_addr, idx;
  u64 ret=1;

  meas_addr = r->rdx;
  idx = r->rcx;

  ret = hc_utpm_pcrextend(vcpu, idx, meas_addr);

  return ret;
}

static u64 do_TV_HC_UTPM_GENRAND(VCPU *vcpu, struct regs *r)
{
  u64 addr, len_addr;
  u64 ret=1;

  addr = r->rcx;
  len_addr = r->rdx;

  ret = hc_utpm_rand(vcpu, addr, len_addr);

  return ret;
}

static u64 do_TV_HC_TPMNVRAM_GETSIZE(VCPU *vcpu, struct regs *r)
{
  u64 size_addr;
  u64 ret=1;

  eu_trace("TV_HC_TPMNVRAM_GETSIZE invoked.");
  size_addr = r->rcx;
  ret = hc_tpmnvram_getsize(vcpu, size_addr);
  return ret;
}

static u64 do_TV_HC_TPMNVRAM_READALL(VCPU *vcpu, struct regs *r)
{
  u64 out_addr;
  u64 ret;

  eu_trace("TV_HC_TPMNVRAM_READALL invoked.");
  out_addr = r->rcx;
  ret = hc_tpmnvram_readall(vcpu, out_addr);
  eu_trace("TV_HC_TPMNVRAM_READALL returning %d (%s)", ret, ret ? "FAILURE" : "Success");
  return ret;
}

static u64 do_TV_HC_TPMNVRAM_WRITEALL(VCPU *vcpu, struct regs *r)
{
  u64 in_addr;
  u64 ret = 1;

  eu_trace("TV_HC_TPMNVRAM_WRITEALL invoked.");
  in_addr = r->rcx;
  ret = hc_tpmnvram_writeall(vcpu, in_addr);
  return ret;
}
#endif

u64 tv_app_handlehypercall(VCPU *vcpu, struct regs *r)
{	
  struct _svm_vmcbfields * linux_vmcb;
  u64 cmd;

  u64 status = APP_SUCCESS;
  u64 ret = 0;

//#ifdef __MP_VERSION__
//  xmhf_smpguest_quiesce(vcpu);
//#endif

  if (vcpu->cpu_vendor == CPU_VENDOR_INTEL) {
    cmd = (u64)r->rax;
    linux_vmcb = 0;
  } else if (vcpu->cpu_vendor == CPU_VENDOR_AMD) {
    linux_vmcb = (struct _svm_vmcbfields *)(vcpu->vmcb_vaddr_ptr);
    cmd = (u64)linux_vmcb->rax;
  } else {
    printf("unknown cpu vendor type!\n");
    HALT();
  }

#define HANDLE(hc) case hc: ret = do_ ## hc (vcpu, r); break

  switch (cmd) {
    HANDLE( TV_HC_TEST );
    // XUM: PAL registration-related code
#ifdef __PAL__
    HANDLE( TV_HC_REG );
    HANDLE( TV_HC_UNREG );
    HANDLE( TV_HC_SHARE );
#endif
    //XUM: micro-TPM related code
#ifdef __UTPM__
    HANDLE( TV_HC_UTPM_SEAL_DEPRECATED );
    HANDLE( TV_HC_UTPM_UNSEAL );
    HANDLE( TV_HC_UTPM_SEAL );
    HANDLE( TV_HC_UTPM_UNSEAL_DEPRECATED );
    HANDLE( TV_HC_UTPM_QUOTE );
    HANDLE( TV_HC_UTPM_ID_GETPUB );
    HANDLE( TV_HC_UTPM_QUOTE_DEPRECATED );
    HANDLE( TV_HC_UTPM_PCRREAD );
    HANDLE( TV_HC_UTPM_PCREXT );
    HANDLE( TV_HC_UTPM_GENRAND );
    HANDLE( TV_HC_TPMNVRAM_GETSIZE );
    HANDLE( TV_HC_TPMNVRAM_READALL );
    HANDLE( TV_HC_TPMNVRAM_WRITEALL );
#endif
    //XUM: handle vcpu locking/unlocking
    //HANDLE( TV_HC_CAT_INIT);
    HANDLE( TV_HC_VCPU_LOCK);
    HANDLE( TV_HC_VCPU_UNLOCK);
    HANDLE( TV_HC_INIT_PMC);
    HANDLE( TV_HC_RDPMC);
    HANDLE( TV_HC_RUN);

  default:
    {
      eu_err("FATAL ERROR: Invalid vmmcall cmd (%d)", cmd);
      status = APP_ERROR;
      ret = 1;
    }
  }

#undef HANDLE

  if (vcpu->cpu_vendor == CPU_VENDOR_INTEL) {
    r->rax = ret;
  } else if (vcpu->cpu_vendor == CPU_VENDOR_AMD) {
    linux_vmcb->rax = ret;
  } else {
    printf("unknow cpu vendor type!\n");
    HALT();
  }

//#ifdef __MP_VERSION__
//  xmhf_smpguest_endquiesce(vcpu);
//#endif

  return status;
}

/* EPT violation handler */
u64 tv_app_handleintercept_hwpgtblviolation(VCPU *vcpu,
                                            struct regs __attribute__((unused)) *r, u64 gpa, u64 gva, u64 violationcode)
{
  u64 ret;
#if defined(__LDN_TV_INTEGRATION__)  
  (void)gva;
#endif //__LDN_TV_INTEGRATION__

//#ifdef __MP_VERSION__
//  xmhf_smpguest_quiesce(vcpu);
//#endif

#ifdef	__PAL__
#if !defined(__LDN_TV_INTEGRATION__)  
  eu_trace("CPU(0x%02x): gva=%#llx, gpa=%#llx, code=%#llx", (int)vcpu->id,
          gva, gpa, violationcode);
  if ((ret = hpt_scode_npf(vcpu, gpa, violationcode)) != 0) {
    eu_trace("FATAL ERROR: Unexpected return value from page fault handling");
    HALT();
  }
#else
	ret = hpt_scode_npf(vcpu, gpa, violationcode);
#endif //__LDN_TV_INTEGRATION__
#else
  (void)vcpu;
  (void)r;
  (void)gpa;
  (void)gva;
  (void)violationcode;
  ret = 0;
#endif

//#ifdef __MP_VERSION__
//  xmhf_smpguest_endquiesce(vcpu);
//#endif

  return ret;
}

u64 tv_app_handleintercept_portaccess(VCPU *vcpu, struct regs __attribute__((unused)) *r, 
                                      u64 portnum, u64 access_type, u64 access_size)
{
//#ifdef __MP_VERSION__
//  xmhf_smpguest_quiesce(vcpu);
//#endif

  eu_err("CPU(0x%02x): Port access intercept feature unimplemented. Halting!", vcpu->id);
  eu_trace("CPU(0x%02x): portnum=0x%08x, access_type=0x%08x, access_size=0x%08x", vcpu->id,
           (u64)portnum, (u64)access_type, (u64)access_size);
  HALT();
  //return APP_IOINTERCEPT_SKIP;
  //return APP_IOINTERCEPT_CHAIN; //chain and do the required I/O    

//#ifdef __MP_VERSION__
//  xmhf_smpguest_endquiesce(vcpu);
//#endif

  return 0; /* XXX DUMMY; keeps compiler happy */
}

void tv_app_handleshutdown(VCPU *vcpu, struct regs __attribute__((unused)) *r)
{
  eu_trace("CPU(0x%02x): Shutdown intercept!", vcpu->id);
  //g_libemhf->xmhf_reboot(vcpu);
  xmhf_baseplatform_reboot(vcpu);
}

/* Local Variables: */
/* mode:c           */
/* indent-tabs-mode:nil */
/* c-basic-offset:2 */
/* End:             */
