/*
 *  QARCH helper routines
 *
 *  Copyright (c) 2007 CodeSourcery
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"

void assign_value(uint64_t* dst, uint64_t value, uint32_t mode);
void set_flags(CPUQARCHState* env, int64_t left_value, int64_t right_value);
uint8_t get_flags(CPUQARCHState* env, uint32_t FLAG);

#if defined(CONFIG_USER_ONLY)

void qarch_cpu_do_interrupt(CPUState *cs)
{
    cs->exception_index = -1;
}

static inline void do_interrupt_qarch_hardirq(CPUQARCHState *env)
{
}

#else

extern int semihosting_enabled;

/* Try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
void tlb_fill(CPUState *cs, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    int ret;

    ret = qarch_cpu_handle_mmu_fault(cs, addr, is_write, mmu_idx);
    if (unlikely(ret)) {
        if (retaddr) {
            /* now we have a real cpu fault */
            cpu_restore_state(cs, retaddr);
        }
        cpu_loop_exit(cs);
    }
}

static void do_rte(CPUQARCHState *env)
{
}

static void do_interrupt_all(CPUQARCHState *env, int is_hw)
{
    CPUState *cs = CPU(qarch_env_get_cpu(env));

    if (!is_hw) {
        switch (cs->exception_index) {
        case EXCP_RTE:
            /* Return from an exception.  */
            do_rte(env);
            return;
        case EXCP_HALT_INSN:
            cs->halted = 1;
            cs->exception_index = EXCP_HLT;
            cpu_loop_exit(cs);
            return;
        }
        if (cs->exception_index >= EXCP_TRAP0
            && cs->exception_index <= EXCP_TRAP15) {
            /* Move the PC after the trap instruction.  */
            cs->halted = 1;
            cs->exception_index = cs->exception_index;
            cpu_loop_exit(cs);
            return;
        }
    }
}

void qarch_cpu_do_interrupt(CPUState *cs)
{
    QArchCPU *cpu = QARCH_CPU(cs->uc, cs);
    CPUQARCHState *env = &cpu->env;

    do_interrupt_all(env, 0);
}

static inline void do_interrupt_qarch_hardirq(CPUQARCHState *env)
{
    do_interrupt_all(env, 1);
}
#endif

bool qarch_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    QArchCPU *cpu = QARCH_CPU(cs->uc, cs);
    CPUQARCHState *env = &cpu->env;

    if (interrupt_request & CPU_INTERRUPT_HARD) {
        /* Real hardware gets the interrupt vector via an IACK cycle
           at this point.  Current emulated hardware doesn't rely on
           this, so we provide/save the vector when the interrupt is
           first signalled.  */
        do_interrupt_qarch_hardirq(env);
        return true;
    }
    return false;
}

static void raise_exception(CPUQARCHState *env, int tt)
{
    CPUState *cs = CPU(qarch_env_get_cpu(env));

    cs->exception_index = tt;
    cpu_loop_exit(cs);
}

void HELPER(raise_exception)(CPUQARCHState *env, uint32_t tt)
{
    raise_exception(env, tt);
}


void assign_value(uint64_t* dst, uint64_t value, uint32_t mode)
{
    switch(mode)
    {
        case 0:
            *dst = (uint8_t)value;
            break;
        case 1:
            *dst = (uint16_t)value;
            break;
        case 2:
            *dst = (uint32_t)value;
            break;
        case 3:
            *dst = (uint64_t)value;
            break;
    }
}

void set_flags(CPUQARCHState* env, int64_t left_value, int64_t right_value)
{
    uint64_t left_uvalue = (uint64_t)left_value;
    uint64_t right_uvalue = (uint64_t)right_value;
    int64_t result = left_value + right_value;
    env->flags = 0;
    if((left_uvalue+right_uvalue)<left_uvalue)
        env->flags |= FLAG_CF;
    if(!result)
        env->flags |= FLAG_ZF;
    if(result < 0)
        env->flags |= FLAG_SF;
    if(left_value > 0 && right_value >0 && result < 0)
        env->flags |= FLAG_OF;
    if(left_value < 0 && right_value <0 && result > 0)
        env->flags |= FLAG_OF;
}

uint8_t get_flags(CPUQARCHState* env, uint32_t FLAG)
{
    return (env->flags & FLAG) != 0;
}


void HELPER(alu)(CPUQARCHState* env, uint64_t rn, uint64_t value, uint32_t mode)
{
    rn = rn & 0xf;
    uint8_t op = mode&0xff;
    uint8_t op_switch = mode >> 8;

    uint64_t real_value;

    if(op_switch)
        real_value = value;
    else
        real_value = env->regs[value&0xf];

    switch(op) 
    {
        case 2:
            set_flags(env, env->regs[rn], real_value);
            env->regs[rn] += real_value;
            break;
        case 3:
            set_flags(env, env->regs[rn], -real_value);
            env->regs[rn] -= real_value;
            break;
        case 4:
            env->regs[rn] *= real_value;
            break;
        case 5:
            if(real_value!=0)
                env->regs[rn] /= real_value;
            break;
        case 6:
            env->regs[rn] %= real_value;
            break;
        case 7:
            env->regs[rn] ^= real_value;
            break;
        case 8:
            env->regs[rn] |= real_value;
            break;
        case 9:
            env->regs[rn] &= real_value;
            break;
        case 0xa:
            env->regs[rn] = env->regs[rn] << real_value;
            break;
        case 0xb:
            env->regs[rn] = env->regs[rn] >> real_value;
            break;
        default:
            break;
    }
}

void HELPER(not)(CPUQARCHState* env, uint64_t rn)
{
    rn = rn & 0xf;
    env->regs[rn] = ~env->regs[rn];
}

void HELPER(pop)(CPUQARCHState* env, uint64_t rn)
{
    if(env->sp<=0)
        return;
    rn = rn & 0xf;
    env->sp -= 1;
    env->regs[rn] = env->stack[env->sp];
}

void HELPER(push)(CPUQARCHState* env, uint64_t rn)
{
    if(env->sp>=0x1000/8)
        return;
    rn = rn & 0xf;
    env->stack[env->sp] = env->regs[rn];
    env->sp += 1;
}

void HELPER(call)(CPUQARCHState* env, uint64_t value, uint64_t next_pc, uint32_t mode)
{
    if(!mode) 
    {
        uint8_t reg = value & 0xf;
        env->pc = env->regs[reg];
    }
    else
    {
        env->pc = value + next_pc;
    }
    env->call_stack[env->call_sp] = next_pc;
    env->call_sp++;
}

void HELPER(ret)(CPUQARCHState* env)
{
    env->call_sp--;
    env->pc = env->call_stack[env->call_sp];
}

void HELPER(cmp)(CPUQARCHState* env, uint64_t rn, uint64_t value, uint32_t mode)
{
    if(mode == 0)
        value = env->regs[value&0xf];
    set_flags(env, env->regs[rn&0xf], -value);    
}

void HELPER(j)(CPUArchState* env, uint64_t value, uint64_t next_pc, uint32_t mode)
{
    uint8_t op = mode&0xff;
    uint8_t op_switch = mode >> 8;
    if(!op_switch)
        value = env->regs[value&0xf];
    else
        value = next_pc + value;

    uint8_t is_j = 0;
    switch(op)
    {
        case 0x13:
            is_j = 1;
            break;
        case 0x14:
            is_j = get_flags(env,FLAG_ZF);
            break;
        case 0x15:
            is_j = !get_flags(env,FLAG_ZF);
            break;
        case 0x16:
            is_j = get_flags(env,FLAG_ZF) || (get_flags(env,FLAG_SF) != get_flags(env,FLAG_OF));
            break;
        case 0x17:
            is_j = !get_flags(env,FLAG_ZF) && (get_flags(env,FLAG_SF) == get_flags(env,FLAG_OF));
            break;
        case 0x18:
            is_j = get_flags(env,FLAG_SF) != get_flags(env,FLAG_OF);
            break;
        case 0x19:
            is_j = get_flags(env,FLAG_SF) == get_flags(env,FLAG_OF);
            break;
        case 0x1a:
            is_j = get_flags(env,FLAG_CF) || get_flags(env,FLAG_ZF);
            break;
        case 0x1b:
            is_j = !get_flags(env,FLAG_CF) && !get_flags(env,FLAG_ZF);
            break;
        case 0x1c:
            is_j = !get_flags(env,FLAG_CF);
            break;
        case 0x1d:
            is_j = get_flags(env,FLAG_CF);
            break;
    }
    if(is_j)
        env->pc = value;
    else
        env->pc = next_pc;
}

void HELPER(syscall)(CPUArchState* env)
{
}
