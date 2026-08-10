/**
 * @file
 * @author  Alexandre Abadie <alexandre.abadie@inria.fr>
 * @brief   Fault handlers implementations
 *
 * Adapted from @url https://wiki.segger.com/Cortex-M_Fault
 *
 * @copyright Inria, 2024
 *
 */

#include <nrf.h>
#include "crash_latch.h"
#include "fault_handlers.h"

volatile crash_latch_t crash_latch __attribute__((section(".non_init")));

void crash_latch_fault(uint32_t fault, uint32_t *sp, uint32_t exc_return) {
    crash_latch.fault   = fault;
    crash_latch.from_ns = (exc_return & (1u << 6)) ? 0u : 1u;  // EXC_RETURN.S clear => non-secure background
    crash_latch.cfsr    = SCB->CFSR;
    crash_latch.sfsr    = SCB->SFSR;
    crash_latch.pc      = 0;
    crash_latch.lr      = 0;
    // Magic is set before touching the stacked frame: reading it can fault
    // again (e.g. after a stacking error), in which case the latch stays
    // valid with pc/lr zeroed.
    crash_latch.magic = CRASH_LATCH_MAGIC;
    crash_latch.lr    = sp[5];
    crash_latch.pc    = sp[6];
}

void crash_latch_watchdog(uint32_t *sp, uint32_t exc_return) {
    NRF_WDT0_S->EVENTS_TIMEOUT = 0;
    // A fault handler that already latched is spinning on purpose, waiting for
    // exactly this timeout. Its snapshot names the fault; this one would only
    // name the spin loop.
    if (crash_latch.magic != CRASH_LATCH_MAGIC) {
        crash_latch_fault(CRASH_FAULT_WATCHDOG, sp, exc_return);
    }
    // The reset is already committed - two 32.768 kHz cycles from the TIMEOUT
    // event - so there is nothing to return to.
    while (1) {
        __NOP();
    }
}

void HardFaultHandler(uint32_t *sp, uint32_t exc_return) {
    if (SCB->HFSR & (SCB_HFSR_DEBUGEVT_Msk)) {
        SCB->HFSR |=  (SCB_HFSR_DEBUGEVT_Msk);      // Reset Hard Fault status
        *(sp + 6u) += 2u;                           // PC is located on stack at SP + 24 bytes. Increment PC by 2 to skip break instruction.
        return;                                     // Return to interrupted application
    }
    crash_latch_fault(CRASH_FAULT_HARD, sp, exc_return);
#if defined(DEBUG)
    hardfault_regs.shcsr.word    = SCB->SHCSR;  // System Handler Control and State Register
    hardfault_regs.mmfsr.byte    = (uint8_t)(SCB->SHCSR & 0xFF);   // MemManage Fault Status Register
    hardfault_regs.mmfar         = SCB->MMFAR;  // MemManage Fault Address Register
    hardfault_regs.bfsr.byte     = (uint8_t)((SCB->SHCSR & 0xFF00) >> 8);    // Bus Fault Status Register
    hardfault_regs.bfar          = SCB->BFAR;   // Bus Fault Manage Address Register
    hardfault_regs.ufsr.halfword = (uint16_t)(SCB->SHCSR >> 16);    // Usage Fault Status Register
    hardfault_regs.hfsr.word     = SCB->HFSR;   // Hard Fault Status Register
    hardfault_regs.dfsr.word     = SCB->DFSR;   // Debug Fault Status Register
    hardfault_regs.afsr          = SCB->AFSR;   // Auxiliary Fault Status Register
    hardfault_regs.regs.r0       = sp[0];       // Register R0
    hardfault_regs.regs.r1       = sp[1];       // Register R1
    hardfault_regs.regs.r2       = sp[2];       // Register R2
    hardfault_regs.regs.r3       = sp[3];       // Register R3
    hardfault_regs.regs.r12      = sp[4];       // Register R12
    hardfault_regs.regs.lr       = sp[5];       // Link register LR
    hardfault_regs.regs.pc       = sp[6];       // Program counter PC
    hardfault_regs.regs.psr.word = sp[7];       // Program status word PSR
#else
    (void)sp;
#endif
    while (1) {
        __NOP();
    }
}


void SecureFaultHandler(uint32_t* sp, uint32_t exc_return) {
    crash_latch_fault(CRASH_FAULT_SECURE, sp, exc_return);
#if defined(DEBUG)
    securefault_reg.sfsr.word    = SCB->SFSR;   // System Handler Control and State Register
    hardfault_regs.regs.r0       = sp[0];       // Register R0
    hardfault_regs.regs.r1       = sp[1];       // Register R1
    hardfault_regs.regs.r2       = sp[2];       // Register R2
    hardfault_regs.regs.r3       = sp[3];       // Register R3
    hardfault_regs.regs.r12      = sp[4];       // Register R12
    hardfault_regs.regs.lr       = sp[5];       // Link register LR
    hardfault_regs.regs.pc       = sp[6];       // Program counter PC
    hardfault_regs.regs.psr.word = sp[7];       // Program status word PSR
#else
    (void)sp;
#endif
    while (1) {
        __NOP();
    }
}
