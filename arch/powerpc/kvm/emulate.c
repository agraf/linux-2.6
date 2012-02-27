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
 * Copyright 2011,2012 Freescale Semiconductor, Inc.
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 * Authors: Alexander Graf <agraf@suse.de>
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
#include "timing.h"
#include "trace.h"

#define OP_TRAP 3
#define OP_TRAP_64 2

#define OP_31_XOP_TRAP      4
#define OP_31_XOP_LWZX      23
#define OP_31_XOP_TRAP_64   68
#define OP_31_XOP_LBZX      87
#define OP_31_XOP_STWX      151
#define OP_31_XOP_STBX      215
#define OP_31_XOP_LBZUX     119
#define OP_31_XOP_STBUX     247
#define OP_31_XOP_LHZX      279
#define OP_31_XOP_LHZUX     311
#define OP_31_XOP_MFSPR     339
#define OP_31_XOP_LHAX      343
#define OP_31_XOP_STHX      407
#define OP_31_XOP_STHUX     439
#define OP_31_XOP_MTSPR     467
#define OP_31_XOP_DCBI      470
#define OP_31_XOP_LWBRX     534
#define OP_31_XOP_TLBSYNC   566
#define OP_31_XOP_STWBRX    662
#define OP_31_XOP_LHBRX     790
#define OP_31_XOP_STHBRX    918

#define OP_LWZ  32
#define OP_LWZU 33
#define OP_LBZ  34
#define OP_LBZU 35
#define OP_STW  36
#define OP_STWU 37
#define OP_STB  38
#define OP_STBU 39
#define OP_LHZ  40
#define OP_LHZU 41
#define OP_LHA  42
#define OP_LHAU 43
#define OP_STH  44
#define OP_STHU 45

struct kvmppc_opentry *kvmppc_list_op;
struct kvmppc_opentry *kvmppc_list_op31;

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

static int kvmppc_emulate_entry(struct kvm_vcpu *vcpu, struct kvmppc_opentry *e,
				u32 inst)
{
	int r = EMULATE_FAIL;

	switch (e->flags & EMUL_FORM_MASK) {
	case EMUL_FORM_D: {
		int (*func)(struct kvm_vcpu *, int, int, int) = (void*)e->func;
		r = func(vcpu, get_rt(inst), get_ra(inst), get_d(inst));
		break;
	}
	case EMUL_FORM_X: {
		int (*func)(struct kvm_vcpu *, int, int, int, int);
		func = (void*)kvmppc_list_op31[get_xop(inst)].func;
		if (func)
			r = func(vcpu, get_rt(inst), get_ra(inst), get_rb(inst),
				 get_rc(inst));
		else
			r = EMULATE_FAIL;
		break;
	}
	}

	if (r == EMULATE_DONE)
		kvmppc_set_pc(vcpu, kvmppc_get_pc(vcpu) + 4);
	if (r == EMULATE_DONE_KEEPNIP)
		r = EMULATE_DONE;

	return r;
}

static int kvmppc_emulate_lwz(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 4, 1);
}

static int kvmppc_emulate_lwzu(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	int r;
	r = kvmppc_handle_load(vcpu->run, vcpu, rt, 4, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_lbz(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 1, 1);
}

static int kvmppc_emulate_lbzu(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	int r;
	r = kvmppc_handle_load(vcpu->run, vcpu, rt, 1, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_stw(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	return kvmppc_handle_store(vcpu->run, vcpu, val, 4, 1);
}

static int kvmppc_emulate_stwu(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	int r;
	ulong val = kvmppc_get_gpr(vcpu, rs);
	r = kvmppc_handle_store(vcpu->run, vcpu, val, 4, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_stb(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	return kvmppc_handle_store(vcpu->run, vcpu, val, 1, 1);
}

static int kvmppc_emulate_stbu(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	int r;
	ulong val = kvmppc_get_gpr(vcpu, rs);
	r = kvmppc_handle_store(vcpu->run, vcpu, val, 1, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_lhz(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 2, 1);
}

static int kvmppc_emulate_lhzu(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	int r;
	r = kvmppc_handle_load(vcpu->run, vcpu, rt, 2, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_lha(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	return kvmppc_handle_loads(vcpu->run, vcpu, rt, 2, 1);
}

static int kvmppc_emulate_lhau(struct kvm_vcpu *vcpu, int rt, int ra, int d)
{
	int r;
	r = kvmppc_handle_loads(vcpu->run, vcpu, rt, 2, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_sth(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	return kvmppc_handle_store(vcpu->run, vcpu, val, 2, 1);
}

static int kvmppc_emulate_sthu(struct kvm_vcpu *vcpu, int rs, int ra, int d)
{
	int r;
	ulong val = kvmppc_get_gpr(vcpu, rs);
	r = kvmppc_handle_store(vcpu->run, vcpu, val, 2, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_lwzx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 4, 1);
}

static int kvmppc_emulate_lbzx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 1, 1);
}

static int kvmppc_emulate_lbzux(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
				int rc)
{
	int r;
	ulong ea = kvmppc_get_gpr(vcpu, rb);
	if (ra)
		ea += kvmppc_get_gpr(vcpu, ra);

	r = kvmppc_handle_load(vcpu->run, vcpu, rt, 1, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_stwx(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
			       int rc)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	return kvmppc_handle_store(vcpu->run, vcpu, val, 4, 1);
}

static int kvmppc_emulate_stbx(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
			       int rc)
{
	ulong val = kvmppc_get_gpr(vcpu, rs);
	return kvmppc_handle_store(vcpu->run, vcpu, val, 1, 1);
}

static int kvmppc_emulate_stbux(struct kvm_vcpu *vcpu, int rs, int ra, int rb,
			       int rc)
{
	int r;
	ulong val = kvmppc_get_gpr(vcpu, rs);
	r = kvmppc_handle_store(vcpu->run, vcpu, val, 1, 1);
	kvmppc_set_gpr(vcpu, rs, vcpu->arch.vaddr_accessed);
	break;
}

static int kvmppc_emulate_lhax(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	return kvmppc_handle_loads(vcpu->run, vcpu, rt, 2, 1);
}

static int kvmppc_emulate_lhzx(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			       int rc)
{
	return kvmppc_handle_load(vcpu->run, vcpu, rt, 2, 1);
}

static int kvmppc_emulate_lhzux(struct kvm_vcpu *vcpu, int rt, int ra, int rb,
			        int rc)
{
	int r;
	r = kvmppc_handle_load(vcpu->run, vcpu, rt, 2, 1);
	kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
	return r;
}

static int kvmppc_emulate_trap(struct kvm_vcpu *vcpu, int to, int ra, int si)
{
#ifdef CONFIG_PPC_BOOK3S
	kvmppc_core_queue_program(vcpu, SRR1_PROGTRAP);
#else
	kvmppc_core_queue_program(vcpu, vcpu->arch.shared->esr | ESR_PTR);
#endif
	return EMULATE_DONE_KEEPNIP;
}

/* XXX to do:
 * lhax
 * lhaux
 * lswx
 * lswi
 * stswx
 * stswi
 * lha
 * lhau
 * lmw
 * stmw
 *
 * XXX is_bigendian should depend on MMU mapping or MSR[LE]
 */
/* XXX Should probably auto-generate instruction decoding for a particular core
 * from opcode tables in the future. */
int kvmppc_emulate_instruction(struct kvm_run *run, struct kvm_vcpu *vcpu)
{
	u32 inst = kvmppc_get_last_inst(vcpu);
	int ra;
	int rb;
	int rs;
	int rt;
	int sprn;
	enum emulation_result emulated = EMULATE_DONE;
	int advance = 1;

	/* this default type might be overwritten by subcategories */
	kvmppc_set_exit_type(vcpu, EMULATED_INST_EXITS);

	pr_debug("Emulating opcode %d / %d\n", get_op(inst), get_xop(inst));

	switch (get_op(inst)) {
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
			advance = 0;
			break;

		case OP_31_XOP_MFSPR:
			sprn = get_sprn(inst);
			rt = get_rt(inst);

			switch (sprn) {
			case SPRN_SRR0:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->srr0);
				break;
			case SPRN_SRR1:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->srr1);
				break;
			case SPRN_PVR:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.pvr); break;
			case SPRN_PIR:
				kvmppc_set_gpr(vcpu, rt, vcpu->vcpu_id); break;
			case SPRN_MSSSR0:
				kvmppc_set_gpr(vcpu, rt, 0); break;

			/* Note: mftb and TBRL/TBWL are user-accessible, so
			 * the guest can always access the real TB anyways.
			 * In fact, we probably will never see these traps. */
			case SPRN_TBWL:
				kvmppc_set_gpr(vcpu, rt, get_tb() >> 32); break;
			case SPRN_TBWU:
				kvmppc_set_gpr(vcpu, rt, get_tb()); break;

			case SPRN_SPRG0:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->sprg0);
				break;
			case SPRN_SPRG1:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->sprg1);
				break;
			case SPRN_SPRG2:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->sprg2);
				break;
			case SPRN_SPRG3:
				kvmppc_set_gpr(vcpu, rt, vcpu->arch.shared->sprg3);
				break;
			/* Note: SPRG4-7 are user-readable, so we don't get
			 * a trap. */

			case SPRN_DEC:
			{
				kvmppc_set_gpr(vcpu, rt,
					       kvmppc_get_dec(vcpu, get_tb()));
				break;
			}
			default:
				emulated = kvmppc_core_emulate_mfspr(vcpu, sprn, rt);
				if (emulated == EMULATE_FAIL) {
					printk("mfspr: unknown spr %x\n", sprn);
					kvmppc_set_gpr(vcpu, rt, 0);
				}
				break;
			}
			kvmppc_set_exit_type(vcpu, EMULATED_MFSPR_EXITS);
			break;

		case OP_31_XOP_STHX:
			rs = get_rs(inst);
			ra = get_ra(inst);
			rb = get_rb(inst);

			emulated = kvmppc_handle_store(run, vcpu,
						       kvmppc_get_gpr(vcpu, rs),
			                               2, 1);
			break;

		case OP_31_XOP_STHUX:
			rs = get_rs(inst);
			ra = get_ra(inst);
			rb = get_rb(inst);

			emulated = kvmppc_handle_store(run, vcpu,
						       kvmppc_get_gpr(vcpu, rs),
			                               2, 1);
			kvmppc_set_gpr(vcpu, ra, vcpu->arch.vaddr_accessed);
			break;

		case OP_31_XOP_MTSPR:
			sprn = get_sprn(inst);
			rs = get_rs(inst);
			switch (sprn) {
			case SPRN_SRR0:
				vcpu->arch.shared->srr0 = kvmppc_get_gpr(vcpu, rs);
				break;
			case SPRN_SRR1:
				vcpu->arch.shared->srr1 = kvmppc_get_gpr(vcpu, rs);
				break;

			/* XXX We need to context-switch the timebase for
			 * watchdog and FIT. */
			case SPRN_TBWL: break;
			case SPRN_TBWU: break;

			case SPRN_MSSSR0: break;

			case SPRN_DEC:
				vcpu->arch.dec = kvmppc_get_gpr(vcpu, rs);
				kvmppc_emulate_dec(vcpu);
				break;

			case SPRN_SPRG0:
				vcpu->arch.shared->sprg0 = kvmppc_get_gpr(vcpu, rs);
				break;
			case SPRN_SPRG1:
				vcpu->arch.shared->sprg1 = kvmppc_get_gpr(vcpu, rs);
				break;
			case SPRN_SPRG2:
				vcpu->arch.shared->sprg2 = kvmppc_get_gpr(vcpu, rs);
				break;
			case SPRN_SPRG3:
				vcpu->arch.shared->sprg3 = kvmppc_get_gpr(vcpu, rs);
				break;

			default:
				emulated = kvmppc_core_emulate_mtspr(vcpu, sprn, rs);
				if (emulated == EMULATE_FAIL)
					printk("mtspr: unknown spr %x\n", sprn);
				break;
			}
			kvmppc_set_exit_type(vcpu, EMULATED_MTSPR_EXITS);
			break;

		case OP_31_XOP_DCBI:
			/* Do nothing. The guest is performing dcbi because
			 * hardware DMA is not snooped by the dcache, but
			 * emulated DMA either goes through the dcache as
			 * normal writes, or the host kernel has handled dcache
			 * coherence. */
			break;

		case OP_31_XOP_LWBRX:
			rt = get_rt(inst);
			emulated = kvmppc_handle_load(run, vcpu, rt, 4, 0);
			break;

		case OP_31_XOP_TLBSYNC:
			break;

		case OP_31_XOP_STWBRX:
			rs = get_rs(inst);
			ra = get_ra(inst);
			rb = get_rb(inst);

			emulated = kvmppc_handle_store(run, vcpu,
						       kvmppc_get_gpr(vcpu, rs),
			                               4, 0);
			break;

		case OP_31_XOP_LHBRX:
			rt = get_rt(inst);
			emulated = kvmppc_handle_load(run, vcpu, rt, 2, 0);
			break;

		case OP_31_XOP_STHBRX:
			rs = get_rs(inst);
			ra = get_ra(inst);
			rb = get_rb(inst);

			emulated = kvmppc_handle_store(run, vcpu,
						       kvmppc_get_gpr(vcpu, rs),
			                               2, 0);
			break;

		default:
			goto use_table;
		}
		break;

	default: {
use_table:
		struct kvmppc_opentry *e = &kvmppc_list_op[get_op(inst)];
		if (e->func) {
			return kvmppc_emulate_entry(vcpu, e, inst);
		} else {
			emulated = EMULATE_FAIL;
		}
	}
	}

	if (emulated == EMULATE_FAIL) {
		emulated = kvmppc_core_emulate_op(run, vcpu, inst, &advance);
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

static void __init kvmppc_emulate_register(int op, int flags, int (*func))
{
	struct kvmppc_opentry entry = {
		.flags = flags,
		.func = func,
	};

	op &= 0x3f;
	kvmppc_list_op[op] = entry;
}

void __init kvmppc_emulate_register_d(int op, int flags,
		int (*func)(struct kvm_vcpu *vcpu, int rt, int ra, int d))
{
	flags |= EMUL_FORM_D;
	kvmppc_emulate_register(op, flags, (void*)func);
}

void __init kvmppc_emulate_register_x(int xop, int flags,
	int (*func)(struct kvm_vcpu *vcpu, int rt, int ra, int rb, int rc))
{
	struct kvmppc_opentry entry = {
		.flags = flags | EMUL_FORM_X,
		.func = (void*)func,
	};

	xop &= 0x3ff;
	kvmppc_list_op31[xop] = entry;
}

void __init kvmppc_emulate_init(void)
{
	kvmppc_list_op = kmalloc(sizeof(struct kvmppc_opentry) * 0x40,
				 GFP_KERNEL | __GFP_ZERO);

	kvmppc_emulate_register_d(OP_LWZ, 0, kvmppc_emulate_lwz);
	kvmppc_emulate_register_d(OP_LWZU, 0, kvmppc_emulate_lwzu);
	kvmppc_emulate_register_d(OP_LBZ, 0, kvmppc_emulate_lbz);
	kvmppc_emulate_register_d(OP_LBZU, 0, kvmppc_emulate_lbzu);
	kvmppc_emulate_register_d(OP_STW, 0, kvmppc_emulate_stw);
	kvmppc_emulate_register_d(OP_STWU, 0, kvmppc_emulate_stwu);
	kvmppc_emulate_register_d(OP_STB, 0, kvmppc_emulate_stb);
	kvmppc_emulate_register_d(OP_STBU, 0, kvmppc_emulate_stbu);
	kvmppc_emulate_register_d(OP_LHZ, 0, kvmppc_emulate_lhz);
	kvmppc_emulate_register_d(OP_LHZU, 0, kvmppc_emulate_lhzu);
	kvmppc_emulate_register_d(OP_LHA, 0, kvmppc_emulate_lha);
	kvmppc_emulate_register_d(OP_LHAU, 0, kvmppc_emulate_lhau);
	kvmppc_emulate_register_d(OP_STH, 0, kvmppc_emulate_sth);
	kvmppc_emulate_register_d(OP_STHU, 0, kvmppc_emulate_sthu);
	kvmppc_emulate_register_d(OP_TRAP, 0, kvmppc_emulate_trap);
#ifdef CONFIG_PPC_BOOK3S
	kvmppc_emulate_register_d(OP_TRAP_64, 0, kvmppc_emulate_trap);
#endif

	/* op31 is special in that it multiplexes */
	kvmppc_list_op31 = kmalloc(sizeof(struct kvmppc_opentry) * 0x400,
				   GFP_KERNEL | __GFP_ZERO);

	kvmppc_emulate_register(31, EMUL_FORM_X, NULL);
	kvmppc_emulate_register_x(OP_31_XOP_LWZX, EMUL_FORM_X,
				  kvmppc_emulate_lwzx);
	kvmppc_emulate_register_x(OP_31_XOP_LBZX, EMUL_FORM_X,
				  kvmppc_emulate_lbzx);
	kvmppc_emulate_register_x(OP_31_XOP_LBZUX, EMUL_FORM_X,
				  kvmppc_emulate_lbzux);
	kvmppc_emulate_register_x(OP_31_XOP_STWX, EMUL_FORM_X,
				  kvmppc_emulate_stwx);
	kvmppc_emulate_register_x(OP_31_XOP_STBX, EMUL_FORM_X,
				  kvmppc_emulate_stbx);
	kvmppc_emulate_register_x(OP_31_XOP_STBUX, EMUL_FORM_X,
				  kvmppc_emulate_stbux);
	kvmppc_emulate_register_x(OP_31_XOP_LHZX, EMUL_FORM_X,
				  kvmppc_emulate_lhzx);
	kvmppc_emulate_register_x(OP_31_XOP_LHZUX, EMUL_FORM_X,
				  kvmppc_emulate_lhzux);
}

void __exit kvmppc_emulate_exit(void)
{
	kfree(kvmppc_list_op);
	kfree(kvmppc_list_op31);
}
