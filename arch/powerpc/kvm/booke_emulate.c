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

static int kvmppc_spr_read_sprg5(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->sprg5;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_sprg5(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->sprg5 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_sprg6(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->sprg6;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_sprg6(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->sprg6 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_sprg7(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->sprg7;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_sprg7(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->sprg7 = val;
	return EMULATE_DONE;
}

static const int ivor2irqprio[] = {
	BOOKE_IRQPRIO_CRITICAL,
	BOOKE_IRQPRIO_MACHINE_CHECK,
	BOOKE_IRQPRIO_DATA_STORAGE,
	BOOKE_IRQPRIO_INST_STORAGE,
	BOOKE_IRQPRIO_EXTERNAL,
	BOOKE_IRQPRIO_ALIGNMENT,
	BOOKE_IRQPRIO_PROGRAM,
	BOOKE_IRQPRIO_FP_UNAVAIL,
	BOOKE_IRQPRIO_SYSCALL,
	BOOKE_IRQPRIO_AP_UNAVAIL,
	BOOKE_IRQPRIO_DECREMENTER,
	BOOKE_IRQPRIO_FIT,
	BOOKE_IRQPRIO_WATCHDOG,
	BOOKE_IRQPRIO_DTLB_MISS,
	BOOKE_IRQPRIO_ITLB_MISS,
	BOOKE_IRQPRIO_DEBUG
};

static int kvmppc_spr_read_ivor0_15(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.ivor[ivor2irqprio[sprn - SPRN_IVOR0]];
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ivor0_15(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ivor[ivor2irqprio[sprn - SPRN_IVOR0]] = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ivor2(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ivor[BOOKE_IRQPRIO_DATA_STORAGE] = val;
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GIVOR2, spr_val);
#endif
	return EMULATE_DONE;
}

static int kvmppc_spr_write_ivor8(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.ivor[BOOKE_IRQPRIO_SYSCALL] = val;
#ifdef CONFIG_KVM_BOOKE_HV
	mtspr(SPRN_GIVOR8, spr_val);
#endif
	return EMULATE_DONE;
}

void __init kvmppc_emulate_booke_init(void)
{
	/*
	 * NOTE: some of these registers are not emulated on BOOKE_HV (GS-mode).
	 * Their backing store is in real registers, and these functions
	 * will return the wrong result if called for them in another context
	 * (such as debugging).
	 */
	kvmppc_emulate_register_x(OP_31_XOP_WRTEE, EMUL_READ_RS,
				  kvmppc_emulate_wrtee);
	kvmppc_emulate_register_x(OP_31_XOP_WRTEEI, 0, kvmppc_emulate_wrteei);
	kvmppc_emulate_register_spr(SPRN_DEAR, 0,
				    kvmppc_spr_read_dear,
				    kvmppc_spr_write_dear);
	kvmppc_emulate_register_spr(SPRN_ESR, 0,
				    kvmppc_spr_read_esr,
				    kvmppc_spr_write_esr);
	kvmppc_emulate_register_spr(SPRN_DBCR0, 0,
				    kvmppc_spr_read_dbcr0,
				    kvmppc_spr_write_dbcr0);
	kvmppc_emulate_register_spr(SPRN_DBCR1, 0,
				    kvmppc_spr_read_dbcr1,
				    kvmppc_spr_write_dbcr1);
	kvmppc_emulate_register_spr(SPRN_DBSR, 0,
				    kvmppc_spr_read_dbsr,
				    kvmppc_spr_write_dbsr);
	kvmppc_emulate_register_spr(SPRN_TSR, 0,
				    kvmppc_spr_read_tsr,
				    kvmppc_spr_write_tsr);
	kvmppc_emulate_register_spr(SPRN_TCR, 0,
				    kvmppc_spr_read_tcr,
				    kvmppc_spr_write_tcr);
	kvmppc_emulate_register_spr(SPRN_IVPR, 0,
				    kvmppc_spr_read_ivpr,
				    kvmppc_spr_write_ivpr);
	/*
	 * Note: SPRG4-7 are user-readable.
	 * These values are loaded into the real SPRGs when resuming the
	 * guest (PR-mode only).
	 */
	kvmppc_emulate_register_spr(SPRN_SPRG4, 0,
				    kvmppc_spr_read_sprg4,
				    kvmppc_spr_write_sprg4);
	kvmppc_emulate_register_spr(SPRN_SPRG5, 0,
				    kvmppc_spr_read_sprg5,
				    kvmppc_spr_write_sprg5);
	kvmppc_emulate_register_spr(SPRN_SPRG6, 0,
				    kvmppc_spr_read_sprg6,
				    kvmppc_spr_write_sprg6);
	kvmppc_emulate_register_spr(SPRN_SPRG7, 0,
				    kvmppc_spr_read_sprg7,
				    kvmppc_spr_write_sprg7);

	kvmppc_emulate_register_spr(SPRN_IVOR0, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR1, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR2, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor2);
	kvmppc_emulate_register_spr(SPRN_IVOR3, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR4, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR5, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR6, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR7, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR8, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor8);
	kvmppc_emulate_register_spr(SPRN_IVOR9, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR10, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR11, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR12, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR13, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR14, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
	kvmppc_emulate_register_spr(SPRN_IVOR15, 0,
				    kvmppc_spr_read_ivor0_15,
				    kvmppc_spr_write_ivor0_15);
}
