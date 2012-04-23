/*
 * Copyright (C) 2008-2011 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Yu Liu, <yu.liu@freescale.com>
 *
 * Description:
 * This file is derived from arch/powerpc/kvm/44x_emulate.c,
 * by Hollis Blanchard <hollisb@us.ibm.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 */

#include <asm/kvm_ppc.h>
#include <asm/disassemble.h>
#include <asm/dbell.h>

#include "booke.h"
#include "e500.h"

#define XOP_MSGSND  206
#define XOP_MSGCLR  238
#define XOP_TLBIVAX 786
#define XOP_TLBSX   914
#define XOP_TLBRE   946
#define XOP_TLBWE   978
#define XOP_TLBILX  18

#ifdef CONFIG_KVM_E500MC
static int dbell2prio(ulong param)
{
	int msg = param & PPC_DBELL_TYPE_MASK;
	int prio = -1;

	switch (msg) {
	case PPC_DBELL_TYPE(PPC_DBELL):
		prio = BOOKE_IRQPRIO_DBELL;
		break;
	case PPC_DBELL_TYPE(PPC_DBELL_CRIT):
		prio = BOOKE_IRQPRIO_DBELL_CRIT;
		break;
	default:
		break;
	}

	return prio;
}

static int kvmppc_emulate_msgclr(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				 int rc)
{
	ulong param = vcpu->arch.gpr[rb];
	int prio = dbell2prio(param);

	if (prio < 0)
		return EMULATE_FAIL;

	clear_bit(prio, &vcpu->arch.pending_exceptions);
	return EMULATE_DONE;
}

static int kvmppc_emulate_msgsnd(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				 int rc)
{
	ulong param = vcpu->arch.gpr[rb];
	int prio = dbell2prio(rb);
	int pir = param & PPC_DBELL_PIR_MASK;
	int i;
	struct kvm_vcpu *cvcpu;

	if (prio < 0)
		return EMULATE_FAIL;

	kvm_for_each_vcpu(i, cvcpu, vcpu->kvm) {
		int cpir = cvcpu->arch.shared->pir;
		if ((param & PPC_DBELL_MSG_BRDCAST) || (cpir == pir)) {
			set_bit(prio, &cvcpu->arch.pending_exceptions);
			kvm_vcpu_kick(cvcpu);
		}
	}

	return EMULATE_DONE;
}
#endif

int kvmppc_core_emulate_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
                           unsigned int inst, int *advance)
{
	int emulated = EMULATE_DONE;
	int ra;
	int rb;
	int rt;

	switch (get_op(inst)) {
	case 31:
		switch (get_xop(inst)) {

		default:
			emulated = EMULATE_FAIL;
		}

		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

int kvmppc_core_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	case SPRN_HID1:
		vcpu_e500->hid1 = spr_val; break;

	case SPRN_MMUCSR0:
		emulated = kvmppc_e500_emul_mt_mmucsr0(vcpu_e500,
				spr_val);
		break;

	/* extra exceptions */
	case SPRN_IVOR32:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL] = spr_val;
		break;
	case SPRN_IVOR33:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA] = spr_val;
		break;
	case SPRN_IVOR34:
		vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND] = spr_val;
		break;
	case SPRN_IVOR35:
		vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR] = spr_val;
		break;
#ifdef CONFIG_KVM_BOOKE_HV
	case SPRN_IVOR36:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL] = spr_val;
		break;
	case SPRN_IVOR37:
		vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT] = spr_val;
		break;
#endif
	}

	return emulated;
}

int kvmppc_core_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	int emulated = EMULATE_DONE;

	switch (sprn) {
	case SPRN_TLB0CFG:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.tlbcfg[0]); break;
	case SPRN_TLB1CFG:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.tlbcfg[1]); break;
	case SPRN_HID1:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500->hid1); break;
	case SPRN_SVR:
		kvmppc_set_gpr(vcpu, rt, vcpu_e500->svr); break;

	case SPRN_MMUCSR0:
		kvmppc_set_gpr(vcpu, rt, 0); break;

	case SPRN_MMUCFG:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.mmucfg); break;

	/* extra exceptions */
	case SPRN_IVOR32:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_UNAVAIL]);
		break;
	case SPRN_IVOR33:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_DATA]);
		break;
	case SPRN_IVOR34:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_SPE_FP_ROUND]);
		break;
	case SPRN_IVOR35:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_PERFORMANCE_MONITOR]);
		break;
#ifdef CONFIG_KVM_BOOKE_HV
	case SPRN_IVOR36:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL]);
		break;
	case SPRN_IVOR37:
		kvmppc_set_gpr(vcpu, rt, vcpu->arch.ivor[BOOKE_IRQPRIO_DBELL_CRIT]);
		break;
#endif
	}

	return emulated;
}

static int kvmppc_emulate_tlbre(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	return kvmppc_e500_emul_tlbre(vcpu);
}

static int kvmppc_emulate_tlbwe(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	return kvmppc_e500_emul_tlbwe(vcpu);
}

static int kvmppc_emulate_tlbsx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	return kvmppc_e500_emul_tlbsx(vcpu, rb);
}

static int kvmppc_emulate_tlbilx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				 int rc)
{
	return kvmppc_e500_emul_tlbilx(vcpu, rt, ra, rb);
}

static int kvmppc_emulate_tlbivax(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				  int rc)
{
	return kvmppc_e500_emul_tlbivax(vcpu, ra, rb);
}

#ifndef CONFIG_KVM_BOOKE_HV

static int kvmppc_spr_read_pid(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->pid[0];
	return EMULATE_DONE;
}

static int kvmppc_spr_write_pid(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	kvmppc_set_pid(vcpu, val);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_pid1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->pid[1];
	return EMULATE_DONE;
}

static int kvmppc_spr_write_pid1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	if (val != 0)
		return EMULATE_FAIL;
	vcpu_e500->pid[1] = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_pid2(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->pid[2];
	return EMULATE_DONE;
}

static int kvmppc_spr_write_pid2(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	if (val != 0)
		return EMULATE_FAIL;
	vcpu_e500->pid[2] = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas0(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas0;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas0(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas0 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas1;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas1 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas2(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas2;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas2(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas2 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas3(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = (u32)vcpu->arch.shared->mas7_3;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas3(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas7_3 &= ~(u64)0xffffffff;
	vcpu->arch.shared->mas7_3 |= val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas4(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas4;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas4(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas4 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas5(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas5;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas5(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas5 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas6(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas6;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas6(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas6 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_mas7(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->mas7 >> 32;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_mas7(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->mas7_3 &= (u64)0xffffffff;
	vcpu->arch.shared->mas7_3 |= (u64)val << 32;
	return EMULATE_DONE;
}

#endif

static int kvmppc_spr_read_l1csr0(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->l1csr0;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_l1csr0(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	vcpu_e500->l1csr0 = val & ~(L1CSR0_DCFI | L1CSR0_CLFC);
	return EMULATE_DONE;
}

static int kvmppc_spr_read_l1csr1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->l1csr1;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_l1csr1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	vcpu_e500->l1csr1 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_hid0(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	*val = vcpu_e500->hid0;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_hid0(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	struct kvmppc_vcpu_e500 *vcpu_e500 = to_e500(vcpu);
	vcpu_e500->hid0 = val;
	return EMULATE_DONE;
}

void __init kvmppc_emulate_e500_init(void)
{
	kvmppc_emulate_register_x(XOP_TLBRE, EMUL_FORM_X, kvmppc_emulate_tlbre);
	kvmppc_emulate_register_x(XOP_TLBWE, EMUL_FORM_X, kvmppc_emulate_tlbwe);
	kvmppc_emulate_register_x(XOP_TLBSX, EMUL_FORM_X, kvmppc_emulate_tlbsx);
	kvmppc_emulate_register_x(XOP_TLBILX, EMUL_FORM_X,
				  kvmppc_emulate_tlbilx);
	kvmppc_emulate_register_x(XOP_TLBIVAX, EMUL_FORM_X,
				  kvmppc_emulate_tlbivax);
#ifdef CONFIG_KVM_E500MC
	kvmppc_emulate_register_x(XOP_MSGSND, EMUL_FORM_X,
				  kvmppc_emulate_msgsnd);
	kvmppc_emulate_register_x(XOP_MSGCLR, EMUL_FORM_X,
				  kvmppc_emulate_msgclr);
#endif

#ifndef CONFIG_KVM_BOOKE_HV
	kvmppc_emulate_register_spr(SPRN_PID, EMUL_FORM_SPR,
				    kvmppc_spr_read_pid,
				    kvmppc_spr_write_pid);
	kvmppc_emulate_register_spr(SPRN_PID1, EMUL_FORM_SPR,
				    kvmppc_spr_read_pid1,
				    kvmppc_spr_write_pid1);
	kvmppc_emulate_register_spr(SPRN_PID2, EMUL_FORM_SPR,
				    kvmppc_spr_read_pid2,
				    kvmppc_spr_write_pid2);
	kvmppc_emulate_register_spr(SPRN_MAS0, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas0,
				    kvmppc_spr_write_mas0);
	kvmppc_emulate_register_spr(SPRN_MAS1, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas1,
				    kvmppc_spr_write_mas1);
	kvmppc_emulate_register_spr(SPRN_MAS2, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas2,
				    kvmppc_spr_write_mas2);
	kvmppc_emulate_register_spr(SPRN_MAS3, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas3,
				    kvmppc_spr_write_mas3);
	kvmppc_emulate_register_spr(SPRN_MAS4, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas4,
				    kvmppc_spr_write_mas4);
	kvmppc_emulate_register_spr(SPRN_MAS5, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas5,
				    kvmppc_spr_write_mas5);
	kvmppc_emulate_register_spr(SPRN_MAS6, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas6,
				    kvmppc_spr_write_mas6);
	kvmppc_emulate_register_spr(SPRN_MAS7, EMUL_FORM_SPR,
				    kvmppc_spr_read_mas7,
				    kvmppc_spr_write_mas7);
#endif
	kvmppc_emulate_register_spr(SPRN_L1CSR0, EMUL_FORM_SPR,
				    kvmppc_spr_read_l1csr0,
				    kvmppc_spr_write_l1csr0);
	kvmppc_emulate_register_spr(SPRN_L1CSR1, EMUL_FORM_SPR,
				    kvmppc_spr_read_l1csr1,
				    kvmppc_spr_write_l1csr1);
	kvmppc_emulate_register_spr(SPRN_HID0, EMUL_FORM_SPR,
				    kvmppc_spr_read_hid0,
				    kvmppc_spr_write_hid0);
}
