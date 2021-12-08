#ifndef QEMU_QARCH_CPU_QOM_H
#define QEMU_QARCH_CPU_QOM_H

#include "qom/cpu.h"

#define TYPE_QARCH_CPU "qarch-cpu"

#define QARCH_CPU_CLASS(uc, klass) \
    OBJECT_CLASS_CHECK(uc, QArchCPUClass, (klass), TYPE_QARCH_CPU)
#define QARCH_CPU(uc, obj) ((QArchCPU *)obj)
#define QARCH_CPU_GET_CLASS(uc, obj) \
    OBJECT_GET_CLASS(uc, QArchCPUClass, (obj), TYPE_QARCH_CPU)

/**
 * QArchCPUClass:
 * @parent_realize: The parent class' realize handler.
 * @parent_reset: The parent class' reset handler.
 *
 * A qarch CPU model.
 */
typedef struct QArchCPUClass {
    /*< private >*/
    CPUClass parent_class;
    /*< public >*/

    DeviceRealize parent_realize;
    void (*parent_reset)(CPUState *cpu);
} QArchCPUClass;

/**
 * QArchCPU:
 * @env: #CPUQARCHState
 *
 * A qarch CPU.
 */
typedef struct QArchCPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUQARCHState env;
} QArchCPU;

static inline QArchCPU *qarch_env_get_cpu(CPUQARCHState *env)
{
    return container_of(env, QArchCPU, env);
}

#define ENV_GET_CPU(e) CPU(qarch_env_get_cpu(e))

#define ENV_OFFSET offsetof(QArchCPU, env)

void qarch_cpu_do_interrupt(CPUState *cpu);
bool qarch_cpu_exec_interrupt(CPUState *cpu, int int_req);
void qarch_cpu_dump_state(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                         int flags);
hwaddr qarch_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
int qarch_cpu_gdb_read_register(CPUState *cpu, uint8_t *buf, int reg);
int qarch_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);

void qarch_cpu_exec_enter(CPUState *cs);
void qarch_cpu_exec_exit(CPUState *cs);

#endif
