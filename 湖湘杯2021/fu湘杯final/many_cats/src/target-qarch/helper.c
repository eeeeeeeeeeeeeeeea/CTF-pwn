/*
 *  qarch op helpers
 *
 *  Copyright (c) 2006-2007 CodeSourcery
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

#include "exec/helper-proto.h"

#define SIGNBIT (1u << 31)


QArchCPU *cpu_qarch_init(struct uc_struct *uc, const char *cpu_model)
{
    QArchCPU *cpu;
    CPUQARCHState *env;
    ObjectClass *oc;

    oc = cpu_class_by_name(uc, TYPE_QARCH_CPU, cpu_model);
    if (oc == NULL) {
        return NULL;
    }
    cpu = QARCH_CPU(uc, object_new(uc, object_class_get_name(oc)));
    env = &cpu->env;

    register_qarch_insns(env);

    object_property_set_bool(uc, OBJECT(cpu), true, "realized", NULL);

    return cpu;
}


#if defined(CONFIG_USER_ONLY)

int qarch_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int rw,
                              int mmu_idx)
{
    QArchCPU *cpu = QARCH_CPU(cs);

    cs->exception_index = EXCP_ACCESS;
    cpu->env.mmu.ar = address;
    return 1;
}

#else

/* MMU */

/* TODO: This will need fixing once the MMU is implemented.  */
hwaddr qarch_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    return addr;
}

int qarch_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int rw,
                              int mmu_idx)
{
    int prot;

    address &= TARGET_PAGE_MASK;
    prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    tlb_set_page(cs, address, address, prot, mmu_idx, TARGET_PAGE_SIZE);
    return 0;
}

/* Notify CPU of a pending interrupt.  Prioritization and vectoring should
   be handled by the interrupt controller.  Real hardware only requests
   the vector when the interrupt is acknowledged by the CPU.  For
   simplicitly we calculate it when the interrupt is signalled.  */
void qarch_set_irq_level(QArchCPU *cpu, int level, uint8_t vector)
{
    CPUState *cs = CPU(cpu);

    if (level) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

#endif

void qarch_cpu_exec_enter(CPUState *cs)
{
    QArchCPU *cpu = QARCH_CPU(cs->uc, cs);
    CPUQARCHState *env = &cpu->env;
    
    env->flags = 0;
}

void qarch_cpu_exec_exit(CPUState *cs)
{
    QArchCPU *cpu = QARCH_CPU(cs->uc, cs);
    CPUQARCHState *env = &cpu->env;

    env->flags = 0;
}
