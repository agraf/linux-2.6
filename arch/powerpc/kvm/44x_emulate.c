/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2008
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <asm/kvm_ppc.h>
#include <asm/dcr.h>
#include <asm/dcr-regs.h>
#include <asm/disassemble.h>
#include <asm/kvm_44x.h>
#include "timing.h"

#include "booke.h"
#include "44x_tlb.h"

#define XOP_MFDCR   323
#define XOP_MTDCR   451
#define XOP_TLBSX   914
#define XOP_ICCCI   966
#define XOP_TLBWE   978

static int kvmppc_emulate_mfdcr(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	int dcrn = (rb << 5) | ra;

	/* The guest may access CPR0 registers to determine the timebase
	 * frequency, and it must know the real host frequency because it
	 * can directly access the timebase registers.
	 *
	 * It would be possible to emulate those accesses in userspace,
	 * but userspace can really only figure out the end frequency.
	 * We could decompose that into the factors that compute it, but
	 * that's tricky math, and it's easier to just report the real
	 * CPR0 values.
	 */
	switch (dcrn) {
	case DCRN_CPR0_CONFIG_ADDR:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.cpr0_cfgaddr);
		break;
	case DCRN_CPR0_CONFIG_DATA:
		local_irq_disable();
		mtdcr(DCRN_CPR0_CONFIG_ADDR, vcpu->arch.cpr0_cfgaddr);
		kvmppc_set_gpr(vcpu, rt, mfdcr(DCRN_CPR0_CONFIG_DATA));
		local_irq_enable();
		break;
	default:
		vcpu->run->dcr.dcrn = dcrn;
		vcpu->run->dcr.data =  0;
		vcpu->run->dcr.is_write = 0;
		vcpu->arch.io_gpr = rt;
		vcpu->arch.dcr_needed = 1;
		kvmppc_account_exit(vcpu, DCR_EXITS);
		return EMULATE_DO_DCR;
	}

	return EMULATE_DONE;
}

static int kvmppc_emulate_mtdcr(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	int dcrn = (rb << 5) | ra;

	/* emulate some access in kernel */
	switch (dcrn) {
	case DCRN_CPR0_CONFIG_ADDR:
		vcpu->arch.cpr0_cfgaddr = kvmppc_get_gpr(vcpu, rs);
		break;
	default:
		vcpu->run->dcr.dcrn = dcrn;
		vcpu->run->dcr.data = kvmppc_get_gpr(vcpu, rs);
		vcpu->run->dcr.is_write = 1;
		vcpu->arch.dcr_needed = 1;
		kvmppc_account_exit(vcpu, DCR_EXITS);
		return EMULATE_DO_DCR;
	}

	return EMULATE_DONE;
}

static int kvmppc_emulate_tlbwe(struct kvm_vcpu *vcpu, int rs, int ra, int ws,
				int rc)
{
	return kvmppc_44x_emul_tlbwe(vcpu, ra, rs, ws);
}

static int kvmppc_emulate_tlbsx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	return kvmppc_44x_emul_tlbsx(vcpu, rt, ra, rb, rc);
}

static int kvmppc_emulate_iccci(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	return EMULATE_DONE;
}

static int kvmppc_spr_read_pid(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.pid;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_pid(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	kvmppc_set_pid(vcpu, val);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mmucr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.mmucr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mmucr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.mmucr = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_ccr0(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.ccr0;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ccr0(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ccr0 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_ccr1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.ccr1;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ccr1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ccr1 = val;
	return EMULATE_DONE;
}

void __init kvmppc_emulate_44x_init(void)
{
	kvmppc_emulate_register_x(XOP_MFDCR, EMUL_WRITE_RT,
				  kvmppc_emulate_mfdcr);
	kvmppc_emulate_register_x(XOP_MTDCR, EMUL_READ_RS,
				  kvmppc_emulate_mtdcr);
	kvmppc_emulate_register_x(XOP_TLBWE, EMUL_READ_RS | EMUL_READ_RA,
				  kvmppc_emulate_tlbwe);
	kvmppc_emulate_register_x(XOP_TLBSX, EMUL_WRITE_RT | EMUL_READ_RA |
				  EMUL_READ_RB, kvmppc_emulate_tlbsx);
	kvmppc_emulate_register_x(XOP_ICCCI, 0, kvmppc_emulate_iccci);
	kvmppc_emulate_register_spr(SPRN_PID, 0,
				    kvmppc_spr_read_pid,
				    kvmppc_spr_write_pid);
	kvmppc_emulate_register_spr(SPRN_MMUCR, 0,
				    kvmppc_spr_read_mmucr,
				    kvmppc_spr_write_mmucr);
	kvmppc_emulate_register_spr(SPRN_CCR0, 0,
				    kvmppc_spr_read_ccr0,
				    kvmppc_spr_write_ccr0);
	kvmppc_emulate_register_spr(SPRN_CCR1, 0,
				    kvmppc_spr_read_ccr1,
				    kvmppc_spr_write_ccr1);
}
