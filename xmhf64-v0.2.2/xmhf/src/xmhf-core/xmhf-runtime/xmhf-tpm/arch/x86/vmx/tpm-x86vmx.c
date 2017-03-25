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

/**
 * EMHF TPM component x86 VMX subarch. backend
 * author: amit vasudevan (amitvasudevan@acm.org) and Jonathan M. McCune
 */

#include <xmhf.h>

//open TPM locality
int xmhf_tpm_arch_x86vmx_open_locality(int locality){
        txt_didvid_t didvid;
        txt_ver_fsbif_emif_t ver;

        // display chipset fuse and device and vendor id info 
        didvid._raw = read_pub_config_reg(TXTCR_DIDVID);
        printf("\n%s: chipset ids: vendor: 0x%x, device: 0x%x, revision: 0x%x", __FUNCTION__,
               didvid.vendor_id, didvid.device_id, didvid.revision_id);
        ver._raw = read_pub_config_reg(TXTCR_VER_FSBIF);
        if ( (ver._raw & 0xffffffff) == 0xffffffff ||
             (ver._raw & 0xffffffff) == 0x00 )         /* need to use VER.EMIF */
            ver._raw = read_pub_config_reg(TXTCR_VER_EMIF);
        printf("\n%s: chipset production fused: %x", __FUNCTION__, ver.prod_fused);
        
        if(txt_is_launched()) {
            write_priv_config_reg(locality == 1 ? TXTCR_CMD_OPEN_LOCALITY1
                                  : TXTCR_CMD_OPEN_LOCALITY2, 0x01);
            read_priv_config_reg(TXTCR_E2STS);   /* just a fence, so ignore return */
            return 0;
        } else {
            printf("\n%s: ERROR: Locality opening UNIMPLEMENTED on Intel without SENTER\n", __FUNCTION__);
            return 1;
        }        
}
