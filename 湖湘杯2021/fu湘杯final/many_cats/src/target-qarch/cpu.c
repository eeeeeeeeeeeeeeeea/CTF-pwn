/*
 * QEMU Motorola 68k CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "hw/qarch/qarch.h"
#include "cpu.h"
#include "qemu-common.h"


static void qarch_cpu_set_pc(CPUState *cs, vaddr value)
{
    QArchCPU *cpu = QARCH_CPU(cs->uc, cs);

    cpu->env.pc = value;
}

static bool qarch_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

static void qarch_set_feature(CPUQARCHState *env, int feature)
{
    env->features |= (1u << feature);
}

/* CPUClass::reset() */
static void qarch_cpu_reset(CPUState *s)
{
    QArchCPU *cpu = QARCH_CPU(s->uc, s);
    QArchCPUClass *mcc = QARCH_CPU_GET_CLASS(s->uc, cpu);
    CPUQARCHState *env = &cpu->env;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUQARCHState, features));
    env->flags = 0;
    env->pc = 0;
    tlb_flush(s, 1);
}

/* CPU models */

static ObjectClass *qarch_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (cpu_model == NULL) {
        return NULL;
    }

    typename = g_strdup_printf("%s-" TYPE_QARCH_CPU, cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    if (oc != NULL && (object_class_dynamic_cast(uc, oc, TYPE_QARCH_CPU) == NULL ||
                       object_class_is_abstract(oc))) {
        return NULL;
    }
    return oc;
}

static void any_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    QArchCPU *cpu = QARCH_CPU(uc, obj);
    CPUQARCHState *env = &cpu->env;

    qarch_set_feature(env, QARCH_FEATURE_CF_ISA_A);
}

typedef struct QArchCPUInfo {
    const char *name;
    void (*instance_init)(struct uc_struct *uc, Object *obj, void *opaque);
} QArchCPUInfo;

static const QArchCPUInfo qarch_cpus[] = {
    { "any",   any_cpu_initfn },
};

static int qarch_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    QArchCPUClass *mcc = QARCH_CPU_GET_CLASS(uc, dev);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(cs->uc, dev, errp);

    return 0;
}

static void qarch_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    QArchCPU *cpu = QARCH_CPU(uc, obj);
    CPUQARCHState *env = &cpu->env;

    cs->env_ptr = env;
    cpu_exec_init(env, opaque);

    if (tcg_enabled(uc)) {
        qarch_tcg_init(uc);
    }
}

static void qarch_cpu_class_init(struct uc_struct *uc, ObjectClass *c, void *data)
{
    QArchCPUClass *mcc = QARCH_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);
    DeviceClass *dc = DEVICE_CLASS(uc, c);

    mcc->parent_realize = dc->realize;
    dc->realize = qarch_cpu_realizefn;

    mcc->parent_reset = cc->reset;
    cc->reset = qarch_cpu_reset;

    cc->class_by_name = qarch_cpu_class_by_name;
    cc->has_work = qarch_cpu_has_work;
    cc->do_interrupt = qarch_cpu_do_interrupt;
    cc->cpu_exec_interrupt = qarch_cpu_exec_interrupt;
    cc->set_pc = qarch_cpu_set_pc;
#ifdef CONFIG_USER_ONLY
    cc->handle_mmu_fault = qarch_cpu_handle_mmu_fault;
#else
    cc->get_phys_page_debug = qarch_cpu_get_phys_page_debug;
#endif
    cc->cpu_exec_enter = qarch_cpu_exec_enter;
    cc->cpu_exec_exit = qarch_cpu_exec_exit;
}

static void register_cpu_type(void *opaque, const QArchCPUInfo *info)
{
    TypeInfo type_info = {0};
    type_info.parent = TYPE_QARCH_CPU,
    type_info.instance_init = info->instance_init,

    type_info.name = g_strdup_printf("%s-" TYPE_QARCH_CPU, info->name);
    type_register(opaque, &type_info);
    g_free((void *)type_info.name);
}

void qarch_cpu_register_types(void *opaque)
{
    const TypeInfo qarch_cpu_type_info = {
        TYPE_QARCH_CPU,
        TYPE_CPU,
        
        sizeof(QArchCPUClass),
        sizeof(QArchCPU),
        opaque,
        
        qarch_cpu_initfn,
        NULL,
        NULL,

        NULL,

        qarch_cpu_class_init,
        NULL,
        NULL,

        true,
    };

    int i;

    type_register_static(opaque, &qarch_cpu_type_info);
    for (i = 0; i < ARRAY_SIZE(qarch_cpus); i++) {
        register_cpu_type(opaque, &qarch_cpus[i]);
    }
}
