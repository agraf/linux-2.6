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
 * Copyright 2011 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <linux/kvm_host.h>
#include <asm/disassemble.h>

#include "booke.h"

#define OP_31_XOP_WRTEE   131
#define OP_31_XOP_WRTEEI  163

static int kvmppc_emulate_wrtee(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	vcpu->arch.shared->msr = (vcpu->arch.shared->msr & ~MSR_EE)
				| (kvmppc_get_gpr(vcpu, rs) & MSR_EE);
	kvmppc_set_exit_type(vcpu, EMULATED_WRTEE_EXITS);
	return EMULATE_DONE;
}

static int kvmppc_emulate_wrteei(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				 int rc)
{
	vcpu->arch.shared->msr = (vcpu->arch.shared->msr & ~MSR_EE)
				| (rb & get_rb(MSR_EE));
	kvmppc_set_exit_type(vcpu, EMULATED_WRTEE_EXITS);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dear(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->dar;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dear(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->dar = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_esr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->esr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_esr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->esr = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dbcr0(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->dbcr0;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dbcr0(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->dbcr0 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dbcr1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->dbcr1;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dbcr1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->dbcr1 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dbsr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.dbsr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dbsr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.dbsr &= ~val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_tsr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.tsr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_tsr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	kvmppc_clr_tsr_bits(vcpu, val);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_tcr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.tcr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_tcr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	kvmppc_set_tcr(vcpu, val);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_ivpr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.ivpr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ivpr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ivpr = val;
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GIVPR, spr_val);
#endif
	return EMULATE_DONE;
}

static int kvmppc_spr_read_sprg4(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->sprg4;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_sprg4(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->sprg4 = val;
	return EMULATE_DONE;
}

/*
 * NOTE: some of these registers are not emulated on BOOKE_HV (GS-mode).
 * Their backing store is in real registers, and these functions
 * will return the wrong result if called for them in another context
 * (such as debugging).
 */
int kvmppc_booke_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	/*
	 * Note: SPRG4-7 are user-readable.
	 * These values are loaded into the real SPRGs when resuming the
	 * guest (PR-mode only).
	 */
	case SPRN_SPRG5:
		vcpu->arch.shared->sprg5 = spr_val; break;
	case SPRN_SPRG6:
		vcpu->arch.shared->sprg6 = spr_val; break;
	case SPRN_SPRG7:
		vcpu->arch.shared->sprg7 = spr_val; break;

	case SPRN_IVOR0:
		vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL] = spr_val;
		break;
	case SPRN_IVOR1:
		vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK] = spr_val;
		break;
	case SPRN_IVOR2:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE] = spr_val;
#ifdef CONFIG_KVM_BOOKE_HV
		mtspr(SPRN_GIVOR2, spr_val);
#endif
		break;
	case SPRN_IVOR3:
		vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE] = spr_val;
		break;
	case SPRN_IVOR4:
		vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL] = spr_val;
		break;
	case SPRN_IVOR5:
		vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT] = spr_val;
		break;
	case SPRN_IVOR6:
		vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM] = spr_val;
		break;
	case SPRN_IVOR7:
		vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR8:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL] = spr_val;
#ifdef CONFIG_KVM_BOOKE_HV
		mtspr(SPRN_GIVOR8, spr_val);
#endif
		break;
	case SPRN_IVOR9:
		vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR10:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER] = spr_val;
		break;
	case SPRN_IVOR11:
		vcpu->arch.ivor[BOOKE_IRQPRIO_FIT] = spr_val;
		break;
	case SPRN_IVOR12:
		vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG] = spr_val;
		break;
	case SPRN_IVOR13:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS] = spr_val;
		break;
	case SPRN_IVOR14:
		vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS] = spr_val;
		break;
	case SPRN_IVOR15:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG] = spr_val;
		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

int kvmppc_booke_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	int emulated = EMULATE_DONE;

	switch (sprn) {
	case SPRN_IVOR0:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_CRITICAL]);
		break;
	case SPRN_IVOR1:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_MACHINE_CHECK]);
		break;
	case SPRN_IVOR2:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE]);
		break;
	case SPRN_IVOR3:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_INST_STORAGE]);
		break;
	case SPRN_IVOR4:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_EXTERNAL]);
		break;
	case SPRN_IVOR5:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_ALIGNMENT]);
		break;
	case SPRN_IVOR6:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_PROGRAM]);
		break;
	case SPRN_IVOR7:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_FP_UNAVAIL]);
		break;
	case SPRN_IVOR8:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL]);
		break;
	case SPRN_IVOR9:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_AP_UNAVAIL]);
		break;
	case SPRN_IVOR10:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DECREMENTER]);
		break;
	case SPRN_IVOR11:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_FIT]);
		break;
	case SPRN_IVOR12:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_WATCHDOG]);
		break;
	case SPRN_IVOR13:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DTLB_MISS]);
		break;
	case SPRN_IVOR14:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_ITLB_MISS]);
		break;
	case SPRN_IVOR15:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DEBUG]);
		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

void __init kvmppc_emulate_booke_init(void)
{
	kvmppc_emulate_register_x(OP_31_XOP_WRTEE, EMUL_FORM_X,
				  kvmppc_emulate_wrtee);
	kvmppc_emulate_register_x(OP_31_XOP_WRTEEI, EMUL_FORM_X,
				  kvmppc_emulate_wrteei);
	kvmppc_emulate_register_spr(SPRN_DEAR, EMUL_FORM_SPR,
				    kvmppc_spr_read_dear,
				    kvmppc_spr_write_dear);
	kvmppc_emulate_register_spr(SPRN_ESR, EMUL_FORM_SPR,
				    kvmppc_spr_read_esr,
				    kvmppc_spr_write_esr);
	kvmppc_emulate_register_spr(SPRN_DBCR0, EMUL_FORM_SPR,
				    kvmppc_spr_read_dbcr0,
				    kvmppc_spr_write_dbcr0);
	kvmppc_emulate_register_spr(SPRN_DBCR1, EMUL_FORM_SPR,
				    kvmppc_spr_read_dbcr1,
				    kvmppc_spr_write_dbcr1);
	kvmppc_emulate_register_spr(SPRN_DBSR, EMUL_FORM_SPR,
				    kvmppc_spr_read_dbsr,
				    kvmppc_spr_write_dbsr);
	kvmppc_emulate_register_spr(SPRN_TSR, EMUL_FORM_SPR,
				    kvmppc_spr_read_tsr,
				    kvmppc_spr_write_tsr);
	kvmppc_emulate_register_spr(SPRN_TCR, EMUL_FORM_SPR,
				    kvmppc_spr_read_tcr,
				    kvmppc_spr_write_tcr);
	kvmppc_emulate_register_spr(SPRN_IVPR, EMUL_FORM_SPR,
				    kvmppc_spr_read_ivpr,
				    kvmppc_spr_write_ivpr);
	kvmppc_emulate_register_spr(SPRN_SPRG4, EMUL_FORM_SPR,
				    kvmppc_spr_read_sprg4,
				    kvmppc_spr_write_sprg4);
}
