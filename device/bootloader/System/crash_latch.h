/**
 * @file
 * @author  Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 * @brief   Crash latch preserved across the watchdog reset that follows a fault
 *
 * The fault handlers snapshot the fault state here. The latch lives in the
 * .non_init RAM section (load="No" in flash_placement.xml, skipped by the
 * startup zeroing loops) so it survives the reset and lets the bootloader
 * publish the crash cause to the network core on the next boot.
 *
 * @copyright Inria, 2026
 *
 */

#ifndef __CRASH_LATCH_H
#define __CRASH_LATCH_H

#include <stdint.h>

#define CRASH_LATCH_MAGIC (0xFA170BADUL)

typedef enum {
    CRASH_FAULT_NONE   = 0,  ///< No fault caught - clean reset (power-on, pin, stop, soft-reset)
    CRASH_FAULT_HARD   = 1,  ///< Secure HardFault, e.g. a bus/usage fault escalated in secure or NSC code
    CRASH_FAULT_SECURE = 2,  ///< SecureFault, e.g. the app writing into secure memory (a NULL store hits AUVIOL)
} crash_fault_t;

typedef struct {
    uint32_t magic;    ///< Equals CRASH_LATCH_MAGIC when the latch holds a valid snapshot
    uint32_t fault;    ///< crash_fault_t value
    uint32_t from_ns;  ///< 1 = non-secure user app faulted (resolve pc/lr against the app .elf); 0 = secure bootloader
    uint32_t cfsr;     ///< Configurable Fault Status Register (MMFSR, BFSR, UFSR)
    uint32_t sfsr;     ///< Secure Fault Status Register
    uint32_t pc;       ///< Stacked program counter at fault (0 if unavailable)
    uint32_t lr;       ///< Stacked link register at fault (0 if unavailable)
} crash_latch_t;

extern volatile crash_latch_t crash_latch;

/**
 * @brief Snapshot the current fault state into the crash latch
 *
 * @param[in]   fault       crash_fault_t value identifying the handler
 * @param[in]   sp          Stack frame of the faulting context (already
 *                          resolved to the secure or non-secure stack by the
 *                          handler trampoline)
 * @param[in]   exc_return  EXC_RETURN seen on handler entry; bit 6 (S) tells
 *                          whether the faulting context was secure
 */
void crash_latch_fault(uint32_t fault, uint32_t *sp, uint32_t exc_return);

#endif  // __CRASH_LATCH_H
