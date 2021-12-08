/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "hw/boards.h"
#include "hw/qarch/qarch.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "cpu.h"
#include "unicorn_common.h"
#include "uc_priv.h"


const int QARCH_REGS_STORAGE_SIZE = offsetof(CPUQARCHState, tlb_table);

static void qarch_set_pc(struct uc_struct *uc, uint64_t address)
{
    ((CPUQARCHState *)uc->current_cpu->env_ptr)->pc = address;
}

void qarch_release(void* ctx);
void qarch_release(void* ctx)
{
    TCGContext *tcg_ctx;
    int i;
    
    release_common(ctx);
    tcg_ctx = (TCGContext *) ctx;
    g_free(tcg_ctx->tb_ctx.tbs);
    g_free(tcg_ctx->qarch_PC);
    g_free(tcg_ctx->qarch_SP);
    g_free(tcg_ctx->qarch_flags);
    for (i = 0; i < 16; i++) {
        g_free(tcg_ctx->qarch_regs[i]);
    }
}

void qarch_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->regs, 0, sizeof(env->regs));
    memset(env->call_stack, 0, sizeof(env->call_stack));

    env->sp = 0;
    env->call_sp = 0;
    env->pc = 0;
}

int qarch_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];
        if (regid >= UC_QARCH_REG_R0 && regid <= UC_QARCH_REG_R15)
            *(int64_t *)value = QARCH_CPU(uc, mycpu)->env.regs[regid - UC_QARCH_REG_R0];
        else {
            switch(regid) {
                default: break;
                case UC_QARCH_REG_PC:
                         *(int64_t *)value = QARCH_CPU(uc, mycpu)->env.pc;
                         break;
            }
        }
    }

    return 0;
}

int qarch_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count)
{
    CPUState *mycpu = uc->cpu;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_QARCH_REG_R0 && regid <= UC_QARCH_REG_R15)
            QARCH_CPU(uc, mycpu)->env.regs[regid - UC_QARCH_REG_R0] = *(uint64_t *)value;
        else {
            switch(regid) {
                default: break;
                case UC_QARCH_REG_PC:
                         QARCH_CPU(uc, mycpu)->env.pc = *(uint64_t *)value;
                         // force to quit execution and flush TB
                         uc->quit_request = true;
                         uc_emu_stop(uc);
                         break;
            }
        }
    }

    return 0;
}

DEFAULT_VISIBILITY
void qarch_uc_init(struct uc_struct* uc)
{
    register_accel_types(uc);
    qarch_cpu_register_types(uc);
    dummy_qarch_machine_init(uc);
    uc->release = qarch_release;
    uc->reg_read = qarch_reg_read;
    uc->reg_write = qarch_reg_write;
    uc->reg_reset = qarch_reg_reset;
    uc->set_pc = qarch_set_pc;
    uc_common_init(uc);
}
