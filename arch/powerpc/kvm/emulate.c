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
 * Copyright IBM Corp. 2007
 * Copyright 2011 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kvm_host.h>
#include <linux/clockchips.h>

#include <asm/reg.h>
#include <asm/time.h>
#include <asm/byteorder.h>
#include <asm/kvm_ppc.h>
#include <asm/disassemble.h>
#include <asm/ppc-opcode.h>
#include "timing.h"
#include "trace.h"

void kvmppc_emulate_dec(struct kvm_vcpu *vcpu)
{
	unsigned long dec_nsec;
	unsigned long long dec_time;

	pr_debug("mtDEC: %x\n", vcpu->arch.dec);
	hrtimer_try_to_cancel(&vcpu->arch.dec_timer);

#ifdef CONFIG_PPC_BOOK3S
	/* mtdec lowers the interrupt line when positive. */
	kvmppc_core_dequeue_dec(vcpu);

	/* POWER4+ triggers a dec interrupt if the value is < 0 */
	if (vcpu->arch.dec & 0x80000000) {
		kvmppc_core_queue_dec(vcpu);
		return;
	}
#endif

#ifdef CONFIG_BOOKE
	/* On BOOKE, DEC = 0 is as good as decrementer not enabled */
	if (vcpu->arch.dec == 0)
		return;
#endif

	/*
	 * The decrementer ticks at the same rate as the timebase, so
	 * that's how we convert the guest DEC value to the number of
	 * host ticks.
	 */

	dec_time = vcpu->arch.dec;
	/*
	 * Guest timebase ticks at the same frequency as host decrementer.
	 * So use the host decrementer calculations for decrementer emulation.
	 */
	dec_time = dec_time << decrementer_clockevent.shift;
	do_div(dec_time, decrementer_clockevent.mult);
	dec_nsec = do_div(dec_time, NSEC_PER_SEC);
	hrtimer_start(&vcpu->arch.dec_timer,
		ktime_set(dec_time, dec_nsec), HRTIMER_MODE_REL);
	vcpu->arch.dec_jiffies = get_tb();
}

u32 kvmppc_get_dec(struct kvm_vcpu *vcpu, u64 tb)
{
	u64 jd = tb - vcpu->arch.dec_jiffies;

#ifdef CONFIG_BOOKE
	if (vcpu->arch.dec < jd)
		return 0;
#endif

	return vcpu->arch.dec - jd;
}

static int kvmppc_emulate_mtspr(struct kvm_vcpu *vcpu, int sprn, int rs)
{
	enum emulation_result emulated = EMULATE_DONE;
	ulong spr_val = kvmppc_get_gpr(vcpu, rs);

	switch (sprn) {
	case SPRN_SRR0:
		kvmppc_set_srr0(vcpu, spr_val);
		break;
	case SPRN_SRR1:
		kvmppc_set_srr1(vcpu, spr_val);
		break;

	/* XXX We need to context-switch the timebase for
	 * watchdog and FIT. */
	case SPRN_TBWL: break;
	case SPRN_TBWU: break;

	case SPRN_DEC:
		vcpu->arch.dec = spr_val;
		kvmppc_emulate_dec(vcpu);
		break;

	case SPRN_SPRG0:
		kvmppc_set_sprg0(vcpu, spr_val);
		break;
	case SPRN_SPRG1:
		kvmppc_set_sprg1(vcpu, spr_val);
		break;
	case SPRN_SPRG2:
		kvmppc_set_sprg2(vcpu, spr_val);
		break;
	case SPRN_SPRG3:
		kvmppc_set_sprg3(vcpu, spr_val);
		break;

	/* PIR can legally be written, but we ignore it */
	case SPRN_PIR: break;

	default:
		emulated = vcpu->kvm->arch.kvm_ops->emulate_mtspr(vcpu, sprn,
								  spr_val);
		if (emulated == EMULATE_FAIL)
			printk(KERN_INFO "mtspr: unknown spr "
				"0x%x\n", sprn);
		break;
	}

	kvmppc_set_exit_type(vcpu, EMULATED_MTSPR_EXITS);

	return emulated;
}

static int kvmppc_emulate_mfspr(struct kvm_vcpu *vcpu, int sprn, int rt)
{
	enum emulation_result emulated = EMULATE_DONE;
	ulong spr_val = 0;

	switch (sprn) {
	case SPRN_SRR0:
		spr_val = kvmppc_get_srr0(vcpu);
		break;
	case SPRN_SRR1:
		spr_val = kvmppc_get_srr1(vcpu);
		break;
	case SPRN_PVR:
		spr_val = vcpu->arch.pvr;
		break;
	case SPRN_PIR:
		spr_val = vcpu->vcpu_id;
		break;

	/* Note: mftb and TBRL/TBWL are user-accessible, so
	 * the guest can always access the real TB anyways.
	 * In fact, we probably will never see these traps. */
	case SPRN_TBWL:
		spr_val = get_tb() >> 32;
		break;
	case SPRN_TBWU:
		spr_val = get_tb();
		break;

	case SPRN_SPRG0:
		spr_val = kvmppc_get_sprg0(vcpu);
		break;
	case SPRN_SPRG1:
		spr_val = kvmppc_get_sprg1(vcpu);
		break;
	case SPRN_SPRG2:
		spr_val = kvmppc_get_sprg2(vcpu);
		break;
	case SPRN_SPRG3:
		spr_val = kvmppc_get_sprg3(vcpu);
		break;
	/* Note: SPRG4-7 are user-readable, so we don't get
	 * a trap. */

	case SPRN_DEC:
		spr_val = kvmppc_get_dec(vcpu, get_tb());
		break;
	default:
		emulated = vcpu->kvm->arch.kvm_ops->emulate_mfspr(vcpu, sprn,
								  &spr_val);
		if (unlikely(emulated == EMULATE_FAIL)) {
			printk(KERN_INFO "mfspr: unknown spr "
				"0x%x\n", sprn);
		}
		break;
	}

	if (emulated == EMULATE_DONE)
		kvmppc_set_gpr(vcpu, rt, spr_val);
	kvmppc_set_exit_type(vcpu, EMULATED_MFSPR_EXITS);

	return emulated;
}

/* XXX Should probably auto-generate instruction decoding for a particular core
 * from opcode tables in the future. */
static int kvmppc_emulate_priv_instruction(struct kvm_vcpu *vcpu, int *advance)
{
	u32 inst = kvmppc_get_last_inst(vcpu);
	int rs = get_rs(inst);
	int rt = get_rt(inst);
	int sprn = get_sprn(inst);
	enum emulation_result emulated = EMULATE_DONE;

	/* this default type might be overwritten by subcategories */
	kvmppc_set_exit_type(vcpu, EMULATED_INST_EXITS);

	pr_debug("Emulating opcode %d / %d\n", get_op(inst), get_xop(inst));

	switch (get_op(inst)) {
	case OP_TRAP:
#ifdef CONFIG_PPC_BOOK3S
	case OP_TRAP_64:
		kvmppc_core_queue_program(vcpu, SRR1_PROGTRAP);
#else
		kvmppc_core_queue_program(vcpu,
					  vcpu->arch.shared->esr | ESR_PTR);
#endif
		*advance = 0;
		break;

	case 31:
		switch (get_xop(inst)) {

		case OP_31_XOP_TRAP:
#ifdef CONFIG_64BIT
		case OP_31_XOP_TRAP_64:
#endif
#ifdef CONFIG_PPC_BOOK3S
			kvmppc_core_queue_program(vcpu, SRR1_PROGTRAP);
#else
			kvmppc_core_queue_program(vcpu,
					vcpu->arch.shared->esr | ESR_PTR);
#endif
			*advance = 0;
			break;

		case OP_31_XOP_MFSPR:
			emulated = kvmppc_emulate_mfspr(vcpu, sprn, rt);
			break;

		case OP_31_XOP_MTSPR:
			emulated = kvmppc_emulate_mtspr(vcpu, sprn, rs);
			break;

		case OP_31_XOP_TLBSYNC:
			break;

		default:
			/* Attempt core-specific emulation below. */
			emulated = EMULATE_FAIL;
		}
		break;

	default:
		emulated = EMULATE_FAIL;
	}

	return emulated;
}

/* Emulates privileged instructions only */
int kvmppc_emulate_instruction(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	u32 inst = kvmppc_get_last_inst(vcpu);
	enum emulation_result emulated;
	int advance = 1;

	emulated = kvmppc_emulate_priv_instruction(vcpu, &advance);
	if (emulated == EMULATE_FAIL) {
		emulated = vcpu->kvm->arch.kvm_ops->emulate_op(run, vcpu, inst,
							       &advance);
		if (emulated == EMULATE_AGAIN) {
			advance = 0;
		} else if (emulated == EMULATE_FAIL) {
			advance = 0;
			printk(KERN_ERR "Couldn't emulate instruction 0x%08x "
			       "(op %d xop %d)\n", inst, get_op(inst), get_xop(inst));
			kvmppc_core_queue_program(vcpu, 0);
		}
	}

	trace_kvm_ppc_instr(inst, kvmppc_get_pc(vcpu), emulated);

	/* Advance past emulated instruction. */
	if (advance)
		kvmppc_set_pc(vcpu, kvmppc_get_pc(vcpu) + 4);

	return emulated;
}
EXPORT_SYMBOL_GPL(kvmppc_emulate_instruction);

static ulong get_addr(struct kvm_vcpu *vcpu, int offset, int ra)
{
	ulong addr = 0;
#if defined(CONFIG_PPC_BOOK3E_64)
	ulong msr_64bit = MSR_CM;
#elif defined(CONFIG_PPC_BOOK3S_64)
	ulong msr_64bit = MSR_SF;
#else
	ulong msr_64bit = 0;
#endif

	if (ra)
		addr = kvmppc_get_gpr(vcpu, ra);

	addr += offset;
	if (!(kvmppc_get_msr(vcpu) & msr_64bit))
		addr = (uint32_t)addr;

	return addr;
}

static int kvmppc_emulate_store(struct kvm_vcpu *vcpu, ulong addr, u64 value,
				int size)
{
	ulong paddr = addr;
	int r;

	if (kvmppc_need_byteswap(vcpu)) {
		switch (size) {
		case 1: *(u8*)&value = value; break;
		case 2: *(u16*)&value = swab16(value); break;
		case 4: *(u32*)&value = swab32(value); break;
		case 8: *(u64*)&value = swab64(value); break;
		}
	} else {
		switch (size) {
		case 1: *(u8*)&value = value; break;
		case 2: *(u16*)&value = value; break;
		case 4: *(u32*)&value = value; break;
		case 8: *(u64*)&value = value; break;
		}
	}

	r = kvmppc_st(vcpu, &paddr, size, &value, true);
	switch (r) {
	case -ENOENT:
#ifdef CONFIG_PPC_BOOK3S
		kvmppc_core_queue_data_storage(vcpu, addr,
			DSISR_ISSTORE | DSISR_NOHPTE);
#else
		kvmppc_core_queue_dtlb_miss(vcpu, addr, ESR_DST | ESR_ST);
#endif
		r = EMULATE_AGAIN;
		break;
	case -EPERM:
#ifdef CONFIG_PPC_BOOK3S
		kvmppc_core_queue_data_storage(vcpu, addr,
			DSISR_ISSTORE | DSISR_PROTFAULT);
#else
		kvmppc_core_queue_data_storage(vcpu, addr, ESR_ST);
#endif
		r = EMULATE_AGAIN;
		break;
	case EMULATE_DO_MMIO:
		vcpu->stat.mmio_exits++;
		vcpu->arch.paddr_accessed = paddr;
		vcpu->arch.vaddr_accessed = addr;
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		r = kvmppc_emulate_loadstore(vcpu);
		break;
	}

	return r;
}

static int kvmppc_emulate_load(struct kvm_vcpu *vcpu, ulong addr, u64 *value,
			       int size)
{
	ulong paddr = addr;
	int r;

	r = kvmppc_ld(vcpu, &paddr, size, value, true);

	switch (r) {
	case EMULATE_DONE:
		switch (size) {
		case 1: *value = *(u8*)value; break;
		case 2: *value = *(u16*)value; break;
		case 4: *value = *(u32*)value; break;
		case 8: break;
		}

		if (kvmppc_need_byteswap(vcpu)) {
			switch (size) {
			case 1: break;
			case 2: *value = swab16(*value); break;
			case 4: *value = swab32(*value); break;
			case 8: *value = swab64(*value); break;
			}
		}
		break;
	case -ENOENT:
#ifdef CONFIG_PPC_BOOK3S
		kvmppc_core_queue_data_storage(vcpu, addr, DSISR_NOHPTE);
#else
		kvmppc_core_queue_dtlb_miss(vcpu, addr, ESR_DST);
#endif
		r = EMULATE_AGAIN;
		break;
	case -EPERM:
#ifdef CONFIG_PPC_BOOK3S
		kvmppc_core_queue_data_storage(vcpu, addr, DSISR_PROTFAULT);
#else
		kvmppc_core_queue_data_storage(vcpu, addr, 0);
#endif
		r = EMULATE_AGAIN;
		break;
	case EMULATE_DO_MMIO:
		vcpu->stat.mmio_exits++;
		vcpu->arch.paddr_accessed = paddr;
		vcpu->arch.vaddr_accessed = addr;
		vcpu->run->exit_reason = KVM_EXIT_MMIO;
		r = kvmppc_emulate_loadstore(vcpu);
		break;
	}

	return r;
}

static int kvmppc_emulate_cmp(struct kvm_vcpu *vcpu, u64 value0, u64 value1,
			      bool cmp_signed, int crf, bool is_32bit)
{
	bool lt, gt, eq;
	u32 cr = 0;
	u32 cr_mask;

	if (cmp_signed) {
		s64 signed0 = value0;
		s64 signed1 = value1;

		if (is_32bit) {
			signed0 = (s64)(s32)signed0;
			signed1 = (s64)(s32)signed1;
		}
		lt = signed0 < signed1;
		gt = signed0 > signed1;
		eq = signed0 == signed1;
	} else {
		if (is_32bit) {
			value0 = (u32)value0;
			value1 = (u32)value1;
		}
		lt = value0 < value1;
		gt = value0 > value1;
		eq = value0 == value1;
	}

	if (lt) cr |= 0x8;
	if (gt) cr |= 0x4;
	if (eq) cr |= 0x2;
	cr <<= ((7 - crf) * 4);
	cr_mask = 0xf << ((7 - crf) * 4);
	cr |= kvmppc_get_cr(vcpu) & ~cr_mask;
	kvmppc_set_cr(vcpu, cr);

	return EMULATE_DONE;
}

int kvmppc_emulate_bc(struct kvm_vcpu *vcpu, u32 inst, bool is_32bit)
{
	u64 addr = (s64)(s16)get_d(inst);
	int bo = get_rt(inst);
	int bi = get_ra(inst);

	/* If not absolute, PC gets added */
	if (!(inst & 0x2))
		addr += kvmppc_get_pc(vcpu);
	if (is_32bit)
		addr = (u32)addr;

	/* LR gets set with LK=1 */
	if (inst & 0x1)
		kvmppc_set_lr(vcpu, kvmppc_get_pc(vcpu) + 4);

	/* CTR handling */
	if (!(bo & 0x4)) {
		ulong ctr = kvmppc_get_ctr(vcpu);
		ctr--;
		if (is_32bit)
			ctr = (u32)ctr;
		kvmppc_set_ctr(vcpu, ctr);
		if (((bo & 0x2) && (ctr != 0)) ||
		   (!(bo & 0x2) && (ctr == 0))) {
			/* Condition not fulfilled, go to next inst */
			return EMULATE_DONE;
		}
	}

	/* CR handling */
	if (!(bo & 0x10)) {
		uint32_t mask = 1 << (3 - (bi & 0x3));
		u32 cr_part = kvmppc_get_cr(vcpu) >> (28 - (bi & ~0x3));
		if (((bo & 0x8) && (cr_part != mask)) ||
		   (!(bo & 0x8) && (cr_part == mask))) {
			/* Condition not fulfilled, go to next inst */
			return EMULATE_DONE;
		}
	}

	/* Off we branch ... */
	kvmppc_set_pc(vcpu, addr);

	/* Indicate that we don't want to advance the PC */
	return EMULATE_AGAIN;
}

int kvmppc_emulate_mtcrf(struct kvm_vcpu *vcpu, u32 inst)
{
	u32 value = kvmppc_get_cr(vcpu);
	u32 new_cr = kvmppc_get_gpr(vcpu, get_rs(inst));
	u32 mask = 0;
	int fxm = (inst >> 12) & 0xff;

	if (fxm & 0x80) mask |= 0xf0000000;
	if (fxm & 0x40) mask |= 0x0f000000;
	if (fxm & 0x20) mask |= 0x00f00000;
	if (fxm & 0x10) mask |= 0x000f0000;
	if (fxm & 0x08) mask |= 0x0000f000;
	if (fxm & 0x04) mask |= 0x00000f00;
	if (fxm & 0x02) mask |= 0x000000f0;
	if (fxm & 0x01) mask |= 0x0000000f;

	value = value & ~mask;
	value |= new_cr & mask;
	kvmppc_set_cr(vcpu, value);
	return EMULATE_DONE;
}

/* Emulates privileged and non-privileged instructions */
int kvmppc_emulate_any_instruction(struct kvm_vcpu *vcpu)
{
	u32 inst = kvmppc_get_last_inst(vcpu);
	ulong addr;
	u64 value;
	bool is_32bit = !(kvmppc_get_msr(vcpu) & MSR_SF);
	enum emulation_result emulated = EMULATE_DONE;
	int advance = 1;

	kvmppc_set_exit_type(vcpu, EMULATED_INST_EXITS);

	/* Try non-privileged instructions */
	switch (get_op(inst)) {
	case OP_STD:
		addr = get_addr(vcpu, (s16)get_d(inst), get_ra(inst));
		value = kvmppc_get_gpr(vcpu, get_rs(inst));
		emulated = kvmppc_emulate_store(vcpu, addr, value, 8);
		break;
	case OP_STW:
		addr = get_addr(vcpu, (s16)get_d(inst), get_ra(inst));
		value = kvmppc_get_gpr(vcpu, get_rs(inst));
		emulated = kvmppc_emulate_store(vcpu, addr, value, 4);
		break;
	case OP_LD:
		addr = get_addr(vcpu, (s16)get_d(inst), get_ra(inst));
		if (addr & 0x3) {
			/* other instructions */
			emulated = EMULATE_FAIL;
			break;
		}
		emulated = kvmppc_emulate_load(vcpu, addr, &value, 8);
		if (emulated == EMULATE_DONE)
			kvmppc_set_gpr(vcpu, get_rt(inst), value);
		break;
	case OP_LWZ:
		addr = get_addr(vcpu, (s16)get_d(inst), get_ra(inst));
		emulated = kvmppc_emulate_load(vcpu, addr, &value, 4);
		kvmppc_set_gpr(vcpu, get_rt(inst), value);
		break;
	case OP_ADDIS:
		value = 0;
		if (get_ra(inst))
			value = kvmppc_get_gpr(vcpu, get_ra(inst));
		value += ((s16)get_d(inst)) << 16;
		kvmppc_set_gpr(vcpu, get_rt(inst), value);
		break;
	case OP_ORI:
		value = kvmppc_get_gpr(vcpu, get_rs(inst));
		value |= get_d(inst);
		kvmppc_set_gpr(vcpu, get_ra(inst), value);
		break;
	case OP_ANDI:
		value = kvmppc_get_gpr(vcpu, get_rs(inst));
		value &= get_d(inst);
		kvmppc_set_gpr(vcpu, get_ra(inst), value);
		kvmppc_emulate_cmp(vcpu, value, 0, true, 0, is_32bit);
		break;
	case OP_CMPI:
		value = kvmppc_get_gpr(vcpu, get_ra(inst));
		kvmppc_emulate_cmp(vcpu, value, (s16)get_d(inst), true,
				   get_rt(inst) >> 2, !(get_rt(inst) & 1));
		break;
	case OP_BC:
		emulated = kvmppc_emulate_bc(vcpu, inst, is_32bit);
		break;
	case 31:
		switch (get_xop(inst)) {
		case OP_31_XOP_MFCR:
			kvmppc_set_gpr(vcpu, get_rt(inst), kvmppc_get_cr(vcpu));
			break;
		case OP_31_XOP_MTCRF:
			emulated = kvmppc_emulate_mtcrf(vcpu, inst);
			break;
		case OP_31_XOP_AND:
			value = kvmppc_get_gpr(vcpu, get_rs(inst));
			value &= kvmppc_get_gpr(vcpu, get_rb(inst));
			kvmppc_set_gpr(vcpu, get_ra(inst), value);
			if (get_rc(inst))
				kvmppc_emulate_cmp(vcpu, value, 0, true, 0,
						   is_32bit);
			break;
		case OP_31_XOP_OR:
			value = kvmppc_get_gpr(vcpu, get_rs(inst));
			value |= kvmppc_get_gpr(vcpu, get_rb(inst));
			kvmppc_set_gpr(vcpu, get_ra(inst), value);
			if (get_rc(inst))
				kvmppc_emulate_cmp(vcpu, value, 0, true, 0,
						   is_32bit);
			break;
		default:
			emulated = EMULATE_FAIL;
			break;
		}
		break;
	default:
		emulated = EMULATE_FAIL;
		break;
	}

	/* Try privileged instructions */
	if (emulated == EMULATE_FAIL)
		emulated = kvmppc_emulate_priv_instruction(vcpu, &advance);

	if (emulated == EMULATE_AGAIN) {
		advance = 0;
	} else if (emulated == EMULATE_FAIL) {
		advance = 0;
		printk(KERN_ERR "Couldn't emulate instruction 0x%08x "
		       "(op %d xop %d)\n", inst, get_op(inst), get_xop(inst));
		kvmppc_core_queue_program(vcpu, 0);
	}

	trace_kvm_ppc_instr(inst, kvmppc_get_pc(vcpu), emulated);

	/* Advance past emulated instruction. */
	if (advance)
		kvmppc_set_pc(vcpu, kvmppc_get_pc(vcpu) + 4);

	return emulated;
}
