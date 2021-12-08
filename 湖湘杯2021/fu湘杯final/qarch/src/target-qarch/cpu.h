/*
 * qarch virtual CPU header
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
#ifndef CPU_QARCH_H
#define CPU_QARCH_H

#define TARGET_LONG_BITS 64

#define CPUArchState struct CPUQARCHState

#include "config.h"
#include "qemu-common.h"
#include "exec/cpu-defs.h"

#include "fpu/softfloat.h"

#define MAX_QREGS 32

#define TARGET_HAS_ICE 1

#define ELF_MACHINE	EM_68K

#define EXCP_ACCESS         2   /* Access (MMU) error.  */
#define EXCP_ADDRESS        3   /* Address error.  */
#define EXCP_ILLEGAL        4   /* Illegal instruction.  */
#define EXCP_DIV0           5   /* Divide by zero */
#define EXCP_PRIVILEGE      8   /* Privilege violation.  */
#define EXCP_TRACE          9
#define EXCP_LINEA          10  /* Unimplemented line-A (MAC) opcode.  */
#define EXCP_LINEF          11  /* Unimplemented line-F (FPU) opcode.  */
#define EXCP_DEBUGNBP       12  /* Non-breakpoint debug interrupt.  */
#define EXCP_DEBEGBP        13  /* Breakpoint debug interrupt.  */
#define EXCP_FORMAT         14  /* RTE format error.  */
#define EXCP_UNINITIALIZED  15
#define EXCP_TRAP0          32   /* User trap #0.  */
#define EXCP_TRAP15         47   /* User trap #15.  */
#define EXCP_UNSUPPORTED    61
#define EXCP_ICE            13

#define EXCP_RTE            0x100
#define EXCP_HALT_INSN      0x101

#define NB_MMU_MODES 2

#define CALL_STACK_SIZE 0x100

typedef struct CPUQARCHState {
    uint64_t regs[16];
    uint64_t pc;
    uint64_t sp;
    uint64_t call_sp;

    /* Condition flags.  */
    uint32_t flags;


    uint64_t call_stack[CALL_STACK_SIZE];
    uint64_t* stack;

    CPU_COMMON

    /* Fields from here on are preserved across CPU reset. */
    uint32_t features;

    // Unicorn engine
    struct uc_struct *uc;
} CPUQARCHState;

#include "cpu-qom.h"

void qarch_tcg_init(struct uc_struct *uc);
QArchCPU *cpu_qarch_init(struct uc_struct *uc, const char *cpu_model);
int cpu_qarch_exec(struct uc_struct *uc, CPUQARCHState *s);
/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_qarch_signal_handler(int host_signum, void *pinfo,
                           void *puc);
void cpu_qarch_flush_flags(CPUQARCHState *, int);

#define FLAG_CF 0x01
#define FLAG_ZF 0x02
#define FLAG_OF 0x04
#define FLAG_SF 0x08

void qarch_set_irq_level(QArchCPU *cpu, int level, uint8_t vector);
void qarch_set_macsr(CPUQARCHState *env, uint32_t val);

void do_qarch_semihosting(CPUQARCHState *env, int nr);

/* There are 4 ColdFire core ISA revisions: A, A+, B and C.
   Each feature covers the subset of instructions common to the
   ISA revisions mentioned.  */

enum qarch_features {
    QARCH_FEATURE_CF_ISA_A,
};

static inline int qarch_feature(CPUQARCHState *env, int feature)
{
    return (env->features & (1u << feature)) != 0;
}

void qarch_cpu_list(FILE *f, fprintf_function cpu_fprintf);

void register_qarch_insns (CPUQARCHState *env);

#define TARGET_PAGE_BITS 13

#define TARGET_PHYS_ADDR_SPACE_BITS 64
#define TARGET_VIRT_ADDR_SPACE_BITS 64

static inline CPUQARCHState *cpu_init(struct uc_struct *uc, const char *cpu_model)
{
    QArchCPU *cpu = cpu_qarch_init(uc, cpu_model);
    if (cpu == NULL) {
        return NULL;
    }
    return &cpu->env;
}

#define cpu_exec cpu_qarch_exec
#define cpu_gen_code cpu_qarch_gen_code
#define cpu_signal_handler cpu_qarch_signal_handler
#define cpu_list qarch_cpu_list

/* MMU modes definitions */
#define MMU_MODE0_SUFFIX _kernel
#define MMU_MODE1_SUFFIX _user
#define MMU_USER_IDX 1
static inline int cpu_mmu_index (CPUQARCHState *env)
{
    return 1;
}

int qarch_cpu_handle_mmu_fault(CPUState *cpu, vaddr address, int rw,
                              int mmu_idx);

#include "exec/cpu-all.h"

static inline void cpu_get_tb_cpu_state(CPUQARCHState *env, target_ulong *pc,
                                        target_ulong *cs_base, int *flags)
{
    *pc = env->pc;
    *cs_base = 0;
    *flags = 0;
}

#include "exec/exec-all.h"

#endif
