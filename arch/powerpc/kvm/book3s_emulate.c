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
 * Copyright SUSE Linux Products GmbH 2009
 *
 * Authors: Alexander Graf <agraf@suse.de>
 */

#include <asm/kvm_ppc.h>
#include <asm/disassemble.h>
#include <asm/kvm_book3s.h>
#include <asm/reg.h>
#include <asm/switch_to.h>

#define XOP_MTMSRD		178
#define XOP_MTSR		210
#define XOP_MTSRIN		242
#define XOP_TLBIEL		274
#define XOP_TLBIE		306
#define XOP_SLBMTE		402
#define XOP_SLBIE		434
#define XOP_SLBIA		498
#define XOP_MFSR		595
#define XOP_MFSRIN		659
#define XOP_DCBA		758
#define XOP_SLBMFEV		851
#define XOP_EIOIO		854
#define XOP_SLBMFEE		915

/* DCBZ is actually 1014, but we patch it to 1010 so we get a trap */
#define XOP_DCBZ		1010

#define OP_LFS			48
#define OP_LFD			50
#define OP_STFS			52
#define OP_STFD			54

#define SPRN_GQR0		912
#define SPRN_GQR1		913
#define SPRN_GQR2		914
#define SPRN_GQR3		915
#define SPRN_GQR4		916
#define SPRN_GQR5		917
#define SPRN_GQR6		918
#define SPRN_GQR7		919

/* Book3S_32 defines mfsrin(v) - but that messes up our abstract
 * function pointers, so let's just disable the define. */
#undef mfsrin

enum priv_level {
	PRIV_PROBLEM = 0,
	PRIV_SUPER = 1,
	PRIV_HYPER = 2,
};

static bool spr_allowed(struct kvm_vcpu *vcpu, enum priv_level level)
{
	/* PAPR VMs only access supervisor SPRs */
	if (vcpu->arch.papr_enabled && (level > PRIV_SUPER))
		return false;

	/* Limit user space to its own small SPR set */
	if ((vcpu->arch.shared->msr & MSR_PR) && level > PRIV_PROBLEM)
		return false;

	return true;
}

static int kvmppc_emulate_mtmsrd(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				 int rc)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	if (rb & 0x20) {
		vcpu->arch.shared->msr &= ~(MSR_RI | MSR_EE);
		vcpu->arch.shared->msr |= val & (MSR_RI | MSR_EE);
	} else {
		kvmppc_set_msr(vcpu, val);
	}
	return EMULATE_DONE;
}

static int kvmppc_emulate_mfsr(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	int srnum = ra & 0xf;

	if (vcpu->arch.mmu.mfsrin) {
		u32 sr = vcpu->arch.mmu.mfsrin(vcpu, srnum);
		kvmppc_set_gpr(vcpu, rt, sr);
	}
	return EMULATE_DONE;
}

static int kvmppc_emulate_mfsrin(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				 int rc)
{
	int srnum = (kvmppc_get_gpr(vcpu, rb) >> 28) & 0xf;
	return kvmppc_emulate_mfsr(vcpu, rt, srnum, 0, 0);
}

static int kvmppc_emulate_mtsr(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
			       int rc)
{
	int srnum = ra & 0xf;

	if (vcpu->arch.mmu.mtsrin)
		vcpu->arch.mmu.mtsrin(vcpu, srnum, kvmppc_get_gpr(vcpu, rs));

	return EMULATE_DONE;
}

static int kvmppc_emulate_mtsrin(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				 int rc)
{
	int srnum = (kvmppc_get_gpr(vcpu, rb) >> 28) & 0xf;
	return kvmppc_emulate_mtsr(vcpu, rs, srnum, 0, 0);
}

static int kvmppc_emulate_tlbie(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	bool large = (ra & 0x20) ? true : false;
	ulong addr = kvmppc_get_gpr(vcpu, rb);
	vcpu->arch.mmu.tlbie(vcpu, addr, large);
	return EMULATE_DONE;
}

static int kvmppc_emulate_xnop(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	return EMULATE_DONE;
}

static int kvmppc_emulate_slbmte(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				 int rc)
{
	if (!vcpu->arch.mmu.slbmte)
		return EMULATE_FAIL;

	vcpu->arch.mmu.slbmte(vcpu, kvmppc_get_gpr(vcpu, rs),
			      kvmppc_get_gpr(vcpu, rb));
	return EMULATE_DONE;
}

static int kvmppc_emulate_slbie(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	if (!vcpu->arch.mmu.slbie)
		return EMULATE_FAIL;

	vcpu->arch.mmu.slbie(vcpu, kvmppc_get_gpr(vcpu, rb));
	return EMULATE_DONE;
}

static int kvmppc_emulate_slbia(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
				int rc)
{
	if (!vcpu->arch.mmu.slbia)
		return EMULATE_FAIL;

	vcpu->arch.mmu.slbia(vcpu);
	return EMULATE_DONE;
}

static int kvmppc_emulate_slbmfee(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				  int rc)
{
	ulong t;

	if (!vcpu->arch.mmu.slbmfee)
		return EMULATE_FAIL;

	t = vcpu->arch.mmu.slbmfee(vcpu, kvmppc_get_gpr(vcpu, rb));
	kvmppc_set_gpr(vcpu, rt, t);

	return EMULATE_DONE;
}

static int kvmppc_emulate_slbmfev(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				  int rc)
{
	ulong t;

	if (!vcpu->arch.mmu.slbmfev)
		return EMULATE_FAIL;

	t = vcpu->arch.mmu.slbmfev(vcpu, kvmppc_get_gpr(vcpu, rb));
	kvmppc_set_gpr(vcpu, rt, t);

	return EMULATE_DONE;
}

static int kvmppc_emulate_dcbz(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	ulong rb_val = kvmppc_get_gpr(vcpu, rb);
	ulong ra_val = 0;
	ulong addr, vaddr;
	u32 zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	u32 dsisr;
	int r;

	if (ra)
		ra_val = kvmppc_get_gpr(vcpu, ra);

	addr = (ra_val + rb_val) & ~31ULL;
	if (!(vcpu->arch.shared->msr & MSR_SF))
		addr &= 0xffffffff;
	vaddr = addr;

	r = kvmppc_st(vcpu, &addr, 32, zeros, true);
	if ((r == -ENOENT) || (r == -EPERM)) {
		struct kvmppc_book3s_shadow_vcpu *svcpu;

		svcpu = svcpu_get(vcpu);
		*advance = 0;
		vcpu->arch.shared->dar = vaddr;
		svcpu->fault_dar = vaddr;

		dsisr = DSISR_ISSTORE;
		if (r == -ENOENT)
			dsisr |= DSISR_NOHPTE;
		else if (r == -EPERM)
			dsisr |= DSISR_PROTFAULT;

		vcpu->arch.shared->dsisr = dsisr;
		svcpu->fault_dsisr = dsisr;
		svcpu_put(svcpu);

		kvmppc_book3s_queue_irqprio(vcpu,
			BOOK3S_INTERRUPT_DATA_STORAGE);
	}

	return EMULATE_DONE;
}

int kvmppc_core_emulate_op(struct kvm_run *run, struct kvm_vcpu *vcpu,
                           unsigned int inst, int *advance)
{
	int emulated = EMULATE_DONE;

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

	if (emulated == EMULATE_FAIL)
		emulated = kvmppc_emulate_paired_single(run, vcpu);

	return emulated;
}

void kvmppc_set_bat(struct kvm_vcpu *vcpu, struct kvmppc_bat *bat, bool upper,
                    u32 val)
{
	if (upper) {
		/* Upper BAT */
		u32 bl = (val >> 2) & 0x7ff;
		bat->bepi_mask = (~bl << 17);
		bat->bepi = val & 0xfffe0000;
		bat->vs = (val & 2) ? 1 : 0;
		bat->vp = (val & 1) ? 1 : 0;
		bat->raw = (bat->raw & 0xffffffff00000000ULL) | val;
	} else {
		/* Lower BAT */
		bat->brpn = val & 0xfffe0000;
		bat->wimg = (val >> 3) & 0xf;
		bat->pp = val & 3;
		bat->raw = (bat->raw & 0x00000000ffffffffULL) | ((u64)val << 32);
	}
}

static struct kvmppc_bat *kvmppc_find_bat(struct kvm_vcpu *vcpu, int sprn)
{
	struct kvmppc_vcpu_book3s *vcpu_book3s = to_book3s(vcpu);
	struct kvmppc_bat *bat;

	switch (sprn) {
	case SPRN_IBAT0U ... SPRN_IBAT3L:
		bat = &vcpu_book3s->ibat[(sprn - SPRN_IBAT0U) / 2];
		break;
	case SPRN_IBAT4U ... SPRN_IBAT7L:
		bat = &vcpu_book3s->ibat[4 + ((sprn - SPRN_IBAT4U) / 2)];
		break;
	case SPRN_DBAT0U ... SPRN_DBAT3L:
		bat = &vcpu_book3s->dbat[(sprn - SPRN_DBAT0U) / 2];
		break;
	case SPRN_DBAT4U ... SPRN_DBAT7L:
		bat = &vcpu_book3s->dbat[4 + ((sprn - SPRN_DBAT4U) / 2)];
		break;
	default:
		BUG();
	}

	return bat;
}

static int kvmppc_spr_read_sdr1(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	if (!spr_allowed(vcpu, PRIV_HYPER))
		return EMULATE_FAIL;
	*val = to_book3s(vcpu)->sdr1;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_sdr1(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	if (!spr_allowed(vcpu, PRIV_HYPER))
		goto EMULATE_FAIL;
	to_book3s(vcpu)->sdr1 = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dsisr(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->dsisr;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dsisr(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->dsisr = val;
	return EMULATE_DONE;
}

static int kvmppc_spr_read_dar(struct kvm_vcpu *vcpu, int sprn, ulong *val)
{
	*val = vcpu->arch.shared->dar;
	return EMULATE_DONE;
}

static int kvmppc_spr_write_dar(struct kvm_vcpu *vcpu, int sprn, ulong val)
{
	vcpu->arch.shared->dar = val;
	return EMULATE_DONE;
}

int kvmppc_core_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	int emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	case SPRN_HIOR:
		to_book3s(vcpu)->hior = spr_val;
		break;
	case SPRN_IBAT0U ... SPRN_IBAT3L:
	case SPRN_IBAT4U ... SPRN_IBAT7L:
	case SPRN_DBAT0U ... SPRN_DBAT3L:
	case SPRN_DBAT4U ... SPRN_DBAT7L:
	{
		struct kvmppc_bat *bat = kvmppc_find_bat(vcpu, sprn);

		kvmppc_set_bat(vcpu, bat, !(sprn % 2), (u32)spr_val);
		/* BAT writes happen so rarely that we're ok to flush
		 * everything here */
		kvmppc_mmu_pte_flush(vcpu, 0, 0);
		kvmppc_mmu_flush_segments(vcpu);
		break;
	}
	case SPRN_HID0:
		to_book3s(vcpu)->hid[0] = spr_val;
		break;
	case SPRN_HID1:
		to_book3s(vcpu)->hid[1] = spr_val;
		break;
	case SPRN_HID2:
		to_book3s(vcpu)->hid[2] = spr_val;
		break;
	case SPRN_HID2_GEKKO:
		to_book3s(vcpu)->hid[2] = spr_val;
		/* HID2.PSE controls paired single on gekko */
		switch (vcpu->arch.pvr) {
		case 0x00080200:	/* lonestar 2.0 */
		case 0x00088202:	/* lonestar 2.2 */
		case 0x70000100:	/* gekko 1.0 */
		case 0x00080100:	/* gekko 2.0 */
		case 0x00083203:	/* gekko 2.3a */
		case 0x00083213:	/* gekko 2.3b */
		case 0x00083204:	/* gekko 2.4 */
		case 0x00083214:	/* gekko 2.4e (8SE) - retail HW2 */
		case 0x00087200:	/* broadway */
			if (vcpu->arch.hflags & BOOK3S_HFLAG_NATIVE_PS) {
				/* Native paired singles */
			} else if (spr_val & (1 << 29)) { /* HID2.PSE */
				vcpu->arch.hflags |= BOOK3S_HFLAG_PAIRED_SINGLE;
				kvmppc_giveup_ext(vcpu, MSR_FP);
			} else {
				vcpu->arch.hflags &= ~BOOK3S_HFLAG_PAIRED_SINGLE;
			}
			break;
		}
		break;
	case SPRN_HID4:
	case SPRN_HID4_GEKKO:
		to_book3s(vcpu)->hid[4] = spr_val;
		break;
	case SPRN_HID5:
		to_book3s(vcpu)->hid[5] = spr_val;
		/* guest HID5 set can change is_dcbz32 */
		if (vcpu->arch.mmu.is_dcbz32(vcpu) &&
		    (mfmsr() & MSR_HV))
			vcpu->arch.hflags |= BOOK3S_HFLAG_DCBZ32;
		break;
	case SPRN_GQR0:
	case SPRN_GQR1:
	case SPRN_GQR2:
	case SPRN_GQR3:
	case SPRN_GQR4:
	case SPRN_GQR5:
	case SPRN_GQR6:
	case SPRN_GQR7:
		to_book3s(vcpu)->gqr[sprn - SPRN_GQR0] = spr_val;
		break;
	case SPRN_ICTC:
	case SPRN_THRM1:
	case SPRN_THRM2:
	case SPRN_THRM3:
	case SPRN_CTRLF:
	case SPRN_CTRLT:
	case SPRN_L2CR:
	case SPRN_MMCR0_GEKKO:
	case SPRN_MMCR1_GEKKO:
	case SPRN_PMC1_GEKKO:
	case SPRN_PMC2_GEKKO:
	case SPRN_PMC3_GEKKO:
	case SPRN_PMC4_GEKKO:
	case SPRN_WPAR_GEKKO:
		break;
unprivileged:
	default:
		printk(KERN_INFO "KVM: invalid SPR write: %d\n", sprn);
#ifndef DEBUG_SPR
		emulated = EMULATE_FAIL;
#endif
		break;
	}

	return emulated;
}

int kvmppc_core_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	int emulated = EMULATE_DONE;

	switch (sprn) {
	case SPRN_IBAT0U ... SPRN_IBAT3L:
	case SPRN_IBAT4U ... SPRN_IBAT7L:
	case SPRN_DBAT0U ... SPRN_DBAT3L:
	case SPRN_DBAT4U ... SPRN_DBAT7L:
	{
		struct kvmppc_bat *bat = kvmppc_find_bat(vcpu, sprn);

		if (sprn % 2)
			kvmppc_set_gpr(vcpu, rt, bat->raw >> 32);
		else
			kvmppc_set_gpr(vcpu, rt, bat->raw);

		break;
	}
	case SPRN_HIOR:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hior);
		break;
	case SPRN_HID0:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hid[0]);
		break;
	case SPRN_HID1:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hid[1]);
		break;
	case SPRN_HID2:
	case SPRN_HID2_GEKKO:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hid[2]);
		break;
	case SPRN_HID4:
	case SPRN_HID4_GEKKO:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hid[4]);
		break;
	case SPRN_HID5:
		kvmppc_set_gpr(vcpu, rt, to_book3s(vcpu)->hid[5]);
		break;
	case SPRN_CFAR:
	case SPRN_PURR:
		kvmppc_set_gpr(vcpu, rt, 0);
		break;
	case SPRN_GQR0:
	case SPRN_GQR1:
	case SPRN_GQR2:
	case SPRN_GQR3:
	case SPRN_GQR4:
	case SPRN_GQR5:
	case SPRN_GQR6:
	case SPRN_GQR7:
		kvmppc_set_gpr(vcpu, rt,
			       to_book3s(vcpu)->gqr[sprn - SPRN_GQR0]);
		break;
	case SPRN_THRM1:
	case SPRN_THRM2:
	case SPRN_THRM3:
	case SPRN_CTRLF:
	case SPRN_CTRLT:
	case SPRN_L2CR:
	case SPRN_MMCR0_GEKKO:
	case SPRN_MMCR1_GEKKO:
	case SPRN_PMC1_GEKKO:
	case SPRN_PMC2_GEKKO:
	case SPRN_PMC3_GEKKO:
	case SPRN_PMC4_GEKKO:
	case SPRN_WPAR_GEKKO:
		kvmppc_set_gpr(vcpu, rt, 0);
		break;
	default:
unprivileged:
		printk(KERN_INFO "KVM: invalid SPR read: %d\n", sprn);
#ifndef DEBUG_SPR
		emulated = EMULATE_FAIL;
#endif
		break;
	}

	return emulated;
}

u32 kvmppc_alignment_dsisr(struct kvm_vcpu *vcpu, unsigned int inst)
{
	u32 dsisr = 0;

	/*
	 * This is what the spec says about DSISR bits (not mentioned = 0):
	 *
	 * 12:13		[DS]	Set to bits 30:31
	 * 15:16		[X]	Set to bits 29:30
	 * 17			[X]	Set to bit 25
	 *			[D/DS]	Set to bit 5
	 * 18:21		[X]	Set to bits 21:24
	 *			[D/DS]	Set to bits 1:4
	 * 22:26			Set to bits 6:10 (RT/RS/FRT/FRS)
	 * 27:31			Set to bits 11:15 (RA)
	 */

	switch (get_op(inst)) {
	/* D-form */
	case OP_LFS:
	case OP_LFD:
	case OP_STFD:
	case OP_STFS:
		dsisr |= (inst >> 12) & 0x4000;	/* bit 17 */
		dsisr |= (inst >> 17) & 0x3c00; /* bits 18:21 */
		break;
	/* X-form */
	case 31:
		dsisr |= (inst << 14) & 0x18000; /* bits 15:16 */
		dsisr |= (inst << 8)  & 0x04000; /* bit 17 */
		dsisr |= (inst << 3)  & 0x03c00; /* bits 18:21 */
		break;
	default:
		printk(KERN_INFO "KVM: Unaligned instruction 0x%x\n", inst);
		break;
	}

	dsisr |= (inst >> 16) & 0x03ff; /* bits 22:31 */

	return dsisr;
}

ulong kvmppc_alignment_dar(struct kvm_vcpu *vcpu, unsigned int inst)
{
	ulong dar = 0;
	ulong ra;

	switch (get_op(inst)) {
	case OP_LFS:
	case OP_LFD:
	case OP_STFD:
	case OP_STFS:
		ra = get_ra(inst);
		if (ra)
			dar = kvmppc_get_gpr(vcpu, ra);
		dar += (s32)((s16)inst);
		break;
	case 31:
		ra = get_ra(inst);
		if (ra)
			dar = kvmppc_get_gpr(vcpu, ra);
		dar += kvmppc_get_gpr(vcpu, get_rb(inst));
		break;
	default:
		printk(KERN_INFO "KVM: Unaligned instruction 0x%x\n", inst);
		break;
	}

	return dar;
}

void __init kvmppc_emulate_book3s_init(void)
{
	kvmppc_emulate_register_x(XOP_MTMSRD, EMUL_FORM_X,
				  kvmppc_emulate_mtmsrd);
	kvmppc_emulate_register_x(XOP_MFSR, EMUL_FORM_X, kvmppc_emulate_mfsr);
	kvmppc_emulate_register_x(XOP_MFSRIN, EMUL_FORM_X,
				  kvmppc_emulate_mfsrin);
	kvmppc_emulate_register_x(XOP_MTSR, EMUL_FORM_X, kvmppc_emulate_mtsr);
	kvmppc_emulate_register_x(XOP_MTSRIN, EMUL_FORM_X,
				  kvmppc_emulate_mtsrin);
	kvmppc_emulate_register_x(XOP_TLBIE, EMUL_FORM_X, kvmppc_emulate_tlbie);
	kvmppc_emulate_register_x(XOP_TLBIEL, EMUL_FORM_X,
				  kvmppc_emulate_tlbie);
	kvmppc_emulate_register_x(XOP_EIOIO, EMUL_FORM_X, kvmppc_emulate_xnop);
	kvmppc_emulate_register_x(XOP_SLBMTE, EMUL_FORM_X,
				  kvmppc_emulate_slbmte);
	kvmppc_emulate_register_x(XOP_SLBIE, EMUL_FORM_X, kvmppc_emulate_slbie);
	kvmppc_emulate_register_x(XOP_SLBIA, EMUL_FORM_X, kvmppc_emulate_slbia);
	kvmppc_emulate_register_x(XOP_SLBMFEE, EMUL_FORM_X,
				  kvmppc_emulate_slbmfee);
	kvmppc_emulate_register_x(XOP_SLBMFEV, EMUL_FORM_X,
				  kvmppc_emulate_slbmfev);
	kvmppc_emulate_register_x(XOP_DCBA, EMUL_FORM_X, kvmppc_emulate_xnop);
	kvmppc_emulate_register_x(XOP_DCBZ, EMUL_FORM_X, kvmppc_emulate_dcbz);

	kvmppc_emulate_register_spr(SPRN_SDR1, EMUL_FORM_SPR,
				    kvmppc_spr_read_sdr1,
				    kvmppc_spr_write_sdr1);
	kvmppc_emulate_register_spr(SPRN_DSISR, EMUL_FORM_SPR,
				    kvmppc_spr_read_dsisr,
				    kvmppc_spr_write_dsisr);
	kvmppc_emulate_register_spr(SPRN_DAR, EMUL_FORM_SPR,
				    kvmppc_spr_read_dar,
				    kvmppc_spr_write_dar);
}
