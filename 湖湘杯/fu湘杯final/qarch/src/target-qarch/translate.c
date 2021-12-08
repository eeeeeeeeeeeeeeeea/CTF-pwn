/*
 *  qarch translation
 *
 *  Copyright (c) 2005-2007 CodeSourcery
 *  Written by Paul Brook
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "cpu.h"
#include "tcg-op.h"
#include "qemu/log.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "exec/gen-icount.h"

//#define DEBUG_DISPATCH 1

/* Fake floating point.  */
#define tcg_gen_mov_f64 tcg_gen_mov_i64
#define tcg_gen_qemu_ldf64 tcg_gen_qemu_ld64
#define tcg_gen_qemu_stf64 tcg_gen_qemu_st64

#define DISAS_INSN(name)                                                \
    static void disas_##name(CPUQARCHState *env, DisasContext *s,        \
                             uint8_t op)

void qarch_tcg_init(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    char *p;
    int i;

    // tcg_ctx->QREG_FP_RESULT = tcg_global_mem_new_i64(tcg_ctx, TCG_AREG0, offsetof(CPUQARCHState, fp_result), "FP_RESULT");

    tcg_ctx->cpu_halted = tcg_global_mem_new_i32(tcg_ctx, TCG_AREG0,
                                        0-offsetof(QArchCPU, env) +
                                        offsetof(CPUState, halted), "HALTED");

    tcg_ctx->cpu_env = tcg_global_reg_new_ptr(tcg_ctx, TCG_AREG0, "env");

    p = tcg_ctx->cpu_reg_names;

    for (i = 0; i < 16; i++) {
        sprintf(p, "R%d", i);
        if (!uc->init_tcg)
            tcg_ctx->qarch_regs[i] = g_malloc0(sizeof(TCGv));
        *((TCGv *)tcg_ctx->qarch_regs[i]) = tcg_global_mem_new(tcg_ctx, TCG_AREG0,
                offsetof(CPUQARCHState, regs[i]), p);
        p += 3;
    }

    if (!uc->init_tcg)
        tcg_ctx->qarch_PC = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->qarch_PC) = tcg_global_mem_new(tcg_ctx, TCG_AREG0, offsetof(CPUQARCHState, pc), "pc");

    if (!uc->init_tcg)
        tcg_ctx->qarch_SP = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->qarch_SP) = tcg_global_mem_new(tcg_ctx, TCG_AREG0, offsetof(CPUQARCHState, sp), "sp");


    if (!uc->init_tcg)
        tcg_ctx->qarch_flags = g_malloc0(sizeof(TCGv));
    *((TCGv *)tcg_ctx->qarch_flags) = tcg_global_mem_new(tcg_ctx, TCG_AREG0, offsetof(CPUQARCHState, flags), "flags");

    if (!uc->init_tcg) 
        for(int i=0;i<=32;i++)
            tcg_ctx->qarch_opcode_table[i] = NULL;

    uc->init_tcg = true;
}

/* internal defines */
typedef struct DisasContext {
    CPUQARCHState *env;
    target_ulong insn_pc; /* Start of the current instruction.  */
    target_ulong pc;
    int is_jmp;
    int user;
    struct TranslationBlock *tb;
    int singlestep_enabled;
    int is_mem;

    // Unicorn engine
    struct uc_struct *uc;
} DisasContext;

#define DISAS_JUMP_NEXT 4

#if defined(CONFIG_USER_ONLY)
#define IS_USER(s) 1
#else
#define IS_USER(s) s->user
#endif

#define OS_BYTE 0
#define OS_WORD 1
#define OS_LONG 2
#define OS_SINGLE 4
#define OS_DOUBLE 5

typedef void (*disas_proc)(CPUQARCHState *env, DisasContext *s, uint8_t insn);


/* Generate a jump to an immediate address.  */
static void gen_jmp_im(DisasContext *s, uint64_t dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_movi_i64(tcg_ctx, *(TCGv *)tcg_ctx->qarch_PC, dest);
    s->is_jmp = DISAS_JUMP;
}

static void gen_exception(DisasContext *s, uint64_t where, int nr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    gen_jmp_im(s, where);
    gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, nr));
}

/* Generate a jump to an immediate address.  */
static void gen_jmp_tb(DisasContext *s, int n, uint64_t dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TranslationBlock *tb;

    tb = s->tb;
    if (unlikely(s->singlestep_enabled)) {
        gen_exception(s, dest, EXCP_DEBUG);
    } else if ((tb->pc & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK) ||
               (s->pc & TARGET_PAGE_MASK) == (dest & TARGET_PAGE_MASK)) {
        tcg_gen_goto_tb(tcg_ctx, n);
        tcg_gen_movi_i64(tcg_ctx, *(TCGv *)tcg_ctx->qarch_PC, dest);
        tcg_gen_exit_tb(tcg_ctx, (uintptr_t)tb + n);
    } else {
        gen_jmp_im(s, dest);
        tcg_gen_exit_tb(tcg_ctx, 0);
    }
    s->is_jmp = DISAS_TB_JUMP;
}

static uint8_t load_b(CPUQARCHState *env, DisasContext *s)
{
    uint8_t data = cpu_ldub_code(env, s->pc);
    s->pc += 1;
    return data;
}

static uint16_t load_w(CPUQARCHState* env, DisasContext *s)
{
    uint16_t data = cpu_lduw_code(env, s->pc);
    s->pc += 2;
    return bswap16(data);
}

static uint32_t load_l(CPUQARCHState* env, DisasContext *s)
{
    uint32_t data = cpu_ldl_code(env, s->pc);
    s->pc += 4;
    return bswap32(data);
}

static uint64_t load_q(CPUQARCHState* env, DisasContext *s)
{
    uint64_t data = cpu_ldq_code(env, s->pc);
    s->pc += 8;
    return bswap64(data);
}

static inline TCGv_i64 gen_load64(DisasContext * s, TCGv addr)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    TCGv_i64 tmp;
    s->is_mem = 1;
    tmp = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_qemu_ld64(s->uc, tmp, addr, 1);
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_bswap64_i64(tcg_ctx, t0, tmp);
    return t0;
}

static inline void gen_store64(DisasContext *s, TCGv addr, TCGv_i64 val)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    s->is_mem = 1;
    TCGv_i64 t0 = tcg_temp_new_i64(tcg_ctx);
    tcg_gen_bswap64_i64(tcg_ctx, t0, val);
    tcg_gen_qemu_st64(s->uc, t0, addr, 1);
}

static TCGv get_imm(TCGContext* tcg_ctx, CPUQARCHState* env, DisasContext *s, uint32_t data_length)
{
    TCGv imm;
    if(data_length == 0)
        imm = tcg_const_i64(tcg_ctx, load_b(env, s));
    if(data_length == 1)
        imm = tcg_const_i64(tcg_ctx, load_w(env, s));
    if(data_length == 2)
        imm = tcg_const_i64(tcg_ctx, load_l(env, s));
    if(data_length == 3)
        imm = tcg_const_i64(tcg_ctx, load_q(env, s));
    return imm;
}


DISAS_INSN(halt)
{
    load_b(env, s);
    gen_exception(s, s->pc, EXCP_HLT);
}

DISAS_INSN(mov)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv src, dst;

    switch(op_switch & 0xf) 
    {
        case 0:
            dst = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            src = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            if(data_length == 0)
                tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 8);
            if(data_length == 1)
                tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 16);
            if(data_length == 2)
                tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 32);
            if(data_length == 3)
                tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 64);
            return;
        case 1: 
            dst = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            src = gen_load64(s, *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf]);
            tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 64);
            return;
        case 2: {
            dst = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            src = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            gen_store64(s, dst, src);
            return;
        }
        case 3: 
            dst = *(TCGv*)tcg_ctx->qarch_regs[load_b(env, s)&0xf];
            src = get_imm(tcg_ctx, env, s, data_length);
            tcg_gen_deposit_tl(tcg_ctx, dst, dst, src, 0, 64);
            return;
        default:
            return;
    }
}

DISAS_INSN(alu)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv src, dst;

    dst = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    if(op_switch == 0)
        src = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    else
        src = get_imm(tcg_ctx, env, s, data_length);
    gen_helper_alu(tcg_ctx, tcg_ctx->cpu_env, dst, src, tcg_const_i32(tcg_ctx, op | (op_switch << 8)));
}

DISAS_INSN(not)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    load_b(env, s);
    uint8_t reg = load_b(env, s)&0xf;

    gen_helper_not(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i64(tcg_ctx, reg));
}

DISAS_INSN(pop)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    load_b(env, s);
    uint8_t reg = load_b(env, s)&0xf;

    gen_helper_pop(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i64(tcg_ctx, reg));
}

DISAS_INSN(push)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    load_b(env, s);
    uint8_t reg = load_b(env, s)&0xf;

    gen_helper_push(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i64(tcg_ctx, reg));
}

DISAS_INSN(call)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv dst;

    if(op_switch == 0)
        dst = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    else
        dst = get_imm(tcg_ctx, env, s, data_length);
    gen_helper_call(tcg_ctx, tcg_ctx->cpu_env, dst, 
            tcg_const_i64(tcg_ctx, s->pc), tcg_const_i32(tcg_ctx, op_switch));
    s->is_jmp = DISAS_JUMP;
}

DISAS_INSN(ret)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    load_b(env, s);
    gen_helper_ret(tcg_ctx, tcg_ctx->cpu_env);
    s->is_jmp = DISAS_JUMP;
}

DISAS_INSN(cmp)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv src, dst;

    dst = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    if((op_switch&0xf) == 0)
        src = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    else
        src = get_imm(tcg_ctx, env, s, data_length);
    gen_helper_cmp(tcg_ctx, tcg_ctx->cpu_env, dst, src, tcg_const_i32(tcg_ctx, op_switch&0xf));
}

DISAS_INSN(j)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv dst;

    if((op_switch&0xf) == 0)
        dst = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    else
        dst = get_imm(tcg_ctx, env, s, data_length);
    gen_helper_j(tcg_ctx, tcg_ctx->cpu_env, dst, 
            tcg_const_i64(tcg_ctx, s->pc), tcg_const_i32(tcg_ctx, op | (op_switch<<8)));
    s->is_jmp = DISAS_JUMP;
}

DISAS_INSN(syscall)
{
    load_b(env, s);
}

/* Generate a jump to the address in qreg DEST.  */
static void gen_jmp(DisasContext *s, TCGv dest)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    tcg_gen_mov_i64(tcg_ctx, *(TCGv *)tcg_ctx->qarch_PC, dest);
    s->is_jmp = DISAS_JUMP;
}

static void
register_opcode(TCGContext *tcg_ctx, disas_proc proc, uint8_t opcode)
{
  tcg_ctx->qarch_opcode_table[opcode] = proc;
}

void register_qarch_insns (CPUQARCHState *env)
{
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
#define INSN(name, opcode) do { \
        register_opcode(tcg_ctx, disas_##name, 0x##opcode); \
    } while(0)

    INSN(halt, 00);
    INSN(mov,  01);
    INSN(alu,  02);
    INSN(alu,  03);
    INSN(alu,  04);
    INSN(alu,  05);
    INSN(alu,  06);
    INSN(alu,  07);
    INSN(alu,  08);
    INSN(alu,  09);
    INSN(alu,  0a);
    INSN(alu,  0b);
    INSN(not,  0c);
    INSN(pop,  0d);
    INSN(push, 0e);
    INSN(call, 10);
    INSN(ret,  11);
    INSN(cmp,  12);

    INSN(j,  13);
    INSN(j,  14);
    INSN(j,  15);
    INSN(j,  16);
    INSN(j,  17);
    INSN(j,  18);
    INSN(j,  19);
    INSN(j,  1a);
    INSN(j,  1b);
    INSN(j,  1c);
    INSN(j,  1d);

    INSN(syscall, 20);
}


static void disas_qarch_insn(CPUQARCHState * env, DisasContext *s)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx;
    uint8_t op;

    if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT))) {
        tcg_gen_debug_insn_start(tcg_ctx, s->pc);
    }

    // Unicorn: end address tells us to stop emulation
    if (s->pc == s->uc->addr_end) {
        gen_exception(s, s->pc, EXCP_HLT);
        return;
    }

    // Unicorn: trace this instruction on request
    if (HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_CODE, s->pc)) {
        gen_uc_tracecode(tcg_ctx, 0xf1f1f1f1, UC_HOOK_CODE_IDX, env->uc, s->pc);
        // the callback might want to stop emulation immediately
        check_exit_request(tcg_ctx);
    }

    op = cpu_ldub_code(env, s->pc);
    s->pc += 1;

    if(op <= 32 && tcg_ctx->qarch_opcode_table[op] != NULL)
        ((disas_proc)tcg_ctx->qarch_opcode_table[op])(env, s, op);
    else
        gen_exception(s, s->pc, EXCP_HLT);
}


/* generate intermediate code for basic block 'tb'.  */
static inline void
gen_intermediate_code_internal(QArchCPU *cpu, TranslationBlock *tb,
                               bool search_pc)
{
    CPUState *cs = CPU(cpu);
    CPUQARCHState *env = &cpu->env;
    DisasContext dc1, *dc = &dc1;
    uint16_t *gen_opc_end;
    CPUBreakpoint *bp;
    int j, lj;
    target_ulong pc_start;
    int pc_offset;
    int num_insns;
    int max_insns;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    bool block_full = false;

    /* generate intermediate code */
    pc_start = tb->pc;

    dc->tb = tb;
    dc->uc = env->uc;

    gen_opc_end = tcg_ctx->gen_opc_buf + OPC_MAX_SIZE;

    dc->env = env;
    dc->is_jmp = DISAS_NEXT;
    dc->pc = pc_start;
    dc->singlestep_enabled = cs->singlestep_enabled;
    dc->is_mem = 0;
    lj = -1;
    num_insns = 0;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0)
        max_insns = CF_COUNT_MASK;

    // Unicorn: early check to see if the address of this block is the until address
    if (tb->pc == env->uc->addr_end) {
        gen_tb_start(tcg_ctx);
        gen_exception(dc, dc->pc, EXCP_HLT);
        goto done_generating;
    }

    // Unicorn: trace this block on request
    // Only hook this block if it is not broken from previous translation due to
    // full translation cache
    if (!env->uc->block_full && HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_BLOCK, pc_start)) {
        // save block address to see if we need to patch block size later
        env->uc->block_addr = pc_start;
        env->uc->size_arg = tcg_ctx->gen_opparam_buf - tcg_ctx->gen_opparam_ptr + 1;
        gen_uc_tracecode(tcg_ctx, 0xf8f8f8f8, UC_HOOK_BLOCK_IDX, env->uc, pc_start);
    } else {
        env->uc->size_arg = -1;
    }

    gen_tb_start(tcg_ctx);
    do {
        pc_offset = dc->pc - pc_start;
        if (unlikely(!QTAILQ_EMPTY(&cs->breakpoints))) {
            QTAILQ_FOREACH(bp, &cs->breakpoints, entry) {
                if (bp->pc == dc->pc) {
                    gen_exception(dc, dc->pc, EXCP_DEBUG);
                    dc->is_jmp = DISAS_JUMP;
                    break;
                }
            }
            if (dc->is_jmp)
                break;
        }
        if (search_pc) {
            j = tcg_ctx->gen_opc_ptr - tcg_ctx->gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j)
                    tcg_ctx->gen_opc_instr_start[lj++] = 0;
            }
            tcg_ctx->gen_opc_pc[lj] = dc->pc;
            tcg_ctx->gen_opc_instr_start[lj] = 1;
            //tcg_ctx.gen_opc_icount[lj] = num_insns;
        }
        //if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO))
        //    gen_io_start();
        dc->insn_pc = dc->pc;
        disas_qarch_insn(env, dc);
        num_insns++;
    } while (!dc->is_jmp && tcg_ctx->gen_opc_ptr < gen_opc_end &&
            !cs->singlestep_enabled &&
            (pc_offset) < (TARGET_PAGE_SIZE - 32) &&
            num_insns < max_insns);

    /* if too long translation, save this info */
    if (tcg_ctx->gen_opc_ptr >= gen_opc_end || num_insns >= max_insns)
        block_full = true;

    //if (tb->cflags & CF_LAST_IO)
    //    gen_io_end();
    if (unlikely(cs->singlestep_enabled)) {
        /* Make sure the pc is updated, and raise a debug exception.  */
        if (!dc->is_jmp) {
            tcg_gen_movi_i64(tcg_ctx, *(TCGv *)tcg_ctx->qarch_PC, dc->pc);
        }
        gen_helper_raise_exception(tcg_ctx, tcg_ctx->cpu_env, tcg_const_i32(tcg_ctx, EXCP_DEBUG));
    } else {
        switch(dc->is_jmp) {
            case DISAS_NEXT:
                gen_jmp_tb(dc, 0, dc->pc);
                break;
            default:
            case DISAS_JUMP:
            case DISAS_UPDATE:
                /* indicate that the hash table must be used to find the next TB */
                tcg_gen_exit_tb(tcg_ctx, 0);
                break;
            case DISAS_TB_JUMP:
                /* nothing more to generate */
                break;
        }
    }

done_generating:
    gen_tb_end(tcg_ctx, tb, num_insns);
    *tcg_ctx->gen_opc_ptr = INDEX_op_end;

    if (search_pc) {
        j = tcg_ctx->gen_opc_ptr - tcg_ctx->gen_opc_buf;
        lj++;
        while (lj <= j)
            tcg_ctx->gen_opc_instr_start[lj++] = 0;
    } else {
        tb->size = dc->pc - pc_start;
        //tb->icount = num_insns;
    }

    //optimize_flags();
    //expand_target_qops();

    env->uc->block_full = block_full;
}

void gen_intermediate_code(CPUQARCHState *env, TranslationBlock *tb)
{
    gen_intermediate_code_internal(qarch_env_get_cpu(env), tb, false);
}

void gen_intermediate_code_pc(CPUQARCHState *env, TranslationBlock *tb)
{
    gen_intermediate_code_internal(qarch_env_get_cpu(env), tb, true);
}

void restore_state_to_opc(CPUQARCHState *env, TranslationBlock *tb, int pc_pos)
{
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    env->pc = tcg_ctx->gen_opc_pc[pc_pos];
}
