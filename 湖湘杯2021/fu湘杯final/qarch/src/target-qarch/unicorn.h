#ifndef UC_QEMU_TARGET_QARCH_H
#define UC_QEMU_TARGET_QARCH_H

// functions to read & write registers
int qarch_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int qarch_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

void qarch_reg_reset(struct uc_struct *uc);

void qarch_uc_init(struct uc_struct* uc);

extern const int QARCH_REGS_STORAGE_SIZE;
#endif
