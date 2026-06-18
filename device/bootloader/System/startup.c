/**
 * @file
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @brief Startup code and vectors definition
 *
 * @copyright Inria, 2024
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <nrf.h>

#include "clock.h"

extern __NO_RETURN int main(void);

// Import symbols defined by the SEGGER linker
extern void __SEGGER_RTL_init_heap(void *ptr, size_t len);
__attribute__ ((weak, alias("Dummy_Handler"))) void exit(int status);

extern uint32_t __data_load_start__;
extern uint32_t __data_start__;
extern uint32_t __data_end__;
extern uint32_t __text_load_start__;
extern uint32_t __text_start__;
extern uint32_t __text_end__;
extern uint32_t __fast_load_start__;
extern uint32_t __fast_start__;
extern uint32_t __fast_end__;
extern uint32_t __ctors_load_start__;
extern uint32_t __ctors_start__;
extern uint32_t __ctors_end__;
extern uint32_t __dtors_load_start__;
extern uint32_t __dtors_start__;
extern uint32_t __dtors_end__;
extern uint32_t __rodata_load_start__;
extern uint32_t __rodata_start__;
extern uint32_t __rodata_end__;
extern uint32_t __tdata_load_start__;
extern uint32_t __tdata_start__;
extern uint32_t __tdata_end__;

extern uint32_t __bss_start__;
extern uint32_t __bss_end__;
extern uint32_t __tbss_start__;
extern uint32_t __tbss_end__;
extern uint32_t __shared_data_start__;
extern uint32_t __shared_data_end__;

extern uint32_t __heap_start__;
extern uint32_t __heap_end__;

extern uint32_t __stack_start__;
extern uint32_t __stack_end__;
extern uint32_t __stack_process_start__;
extern uint32_t __stack_process_end__;
extern uint32_t __HEAPSIZE__;
extern uint32_t __STACKSIZE__;
extern uint32_t __STACKSIZE_PROCESS__;

__NO_RETURN extern void Reset_Handler(void);
__NO_RETURN void Dummy_Handler(void);

// Exceptions handlers
__attribute__ ((weak, alias("Dummy_Handler"))) void NMI_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void MemManage_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void BusFault_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void UsageFault_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SVC_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void DebugMon_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PendSV_Handler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SysTick_Handler(void);

void HardFault_Handler(void);
void SecureFault_Handler(void);

// External interrupts handlers
__attribute__ ((weak, alias("Dummy_Handler"))) void FPU_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void CACHE_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SPU_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void CLOCK_POWER_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SERIAL0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SERIAL1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SPIM4_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SERIAL2_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SERIAL3_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void GPIOTE0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void SAADC_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void TIMER0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void TIMER1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void TIMER2_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void RTC0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void RTC1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void WDT0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void WDT1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void COMP_LPCOMP_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU2_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU3_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU4_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void EGU5_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PWM0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PWM1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PWM2_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PWM3_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void PDM0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void I2S0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void IPC_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void QSPI_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void NFCT_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void GPIOTE1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void QDEC0_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void QDEC1_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void USBD_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void USBREGULATOR_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void KMU_IRQHandler(void);
__attribute__ ((weak, alias("Dummy_Handler"))) void CRYPTOCELL_IRQHandler(void);

// Vector table
typedef void(*vector_table_t)(void);
extern const vector_table_t _vectors[496];
const vector_table_t _vectors[496] __attribute__((used, section(".vectors"))) = {
    (vector_table_t)&__stack_end__,     //     Initial Stack Pointer
    Reset_Handler,                      //     Reset Handler
    NMI_Handler,                        // -14 NMI Handler
    HardFault_Handler,                  // -13 Hard Fault HandleR
    MemManage_Handler,                  // -12 MPU Fault Handler
    BusFault_Handler,                   // -11 Bus Fault Handler
    UsageFault_Handler,                 // -10 Usage Fault Handler
    SecureFault_Handler,                //  -9 Secure Fault Handler
    0,                                  //     Reserved
    0,                                  //     Reserved
    0,                                  //     Reserved
    SVC_Handler,                        //  -5 SVCall Handler
    DebugMon_Handler,                   //  -4 Debug Monitor Handler
    0,                                  //     Reserved
    PendSV_Handler,                     //  -2 PendSV Handler
    SysTick_Handler,                    //  -1 SysTick Handler

    // External Interrupts
    FPU_IRQHandler,
    CACHE_IRQHandler,
    0,
    SPU_IRQHandler,
    0,
    CLOCK_POWER_IRQHandler,
    0,
    0,
    SERIAL0_IRQHandler,
    SERIAL1_IRQHandler,
    SPIM4_IRQHandler,
    SERIAL2_IRQHandler,
    SERIAL3_IRQHandler,
    GPIOTE0_IRQHandler,
    SAADC_IRQHandler,
    TIMER0_IRQHandler,
    TIMER1_IRQHandler,
    TIMER2_IRQHandler,
    0,
    0,
    RTC0_IRQHandler,
    RTC1_IRQHandler,
    0,
    0,
    WDT0_IRQHandler,
    WDT1_IRQHandler,
    COMP_LPCOMP_IRQHandler,
    EGU0_IRQHandler,
    EGU1_IRQHandler,
    EGU2_IRQHandler,
    EGU3_IRQHandler,
    EGU4_IRQHandler,
    EGU5_IRQHandler,
    PWM0_IRQHandler,
    PWM1_IRQHandler,
    PWM2_IRQHandler,
    PWM3_IRQHandler,
    0,
    PDM0_IRQHandler,
    0,
    I2S0_IRQHandler,
    0,
    IPC_IRQHandler,
    QSPI_IRQHandler,
    0,
    NFCT_IRQHandler,
    0,
    GPIOTE1_IRQHandler,
    0,
    0,
    0,
    QDEC0_IRQHandler,
    QDEC1_IRQHandler,
    0,
    USBD_IRQHandler,
    USBREGULATOR_IRQHandler,
    0,
    KMU_IRQHandler,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    CRYPTOCELL_IRQHandler,
};

// Entry point
void Reset_Handler(void) {
    SCB->CPACR |= ((3UL << 10*2)|(3UL << 11*2));  /* set CP10 and CP11 Full Access */

    __set_MSP((uint32_t)&__stack_end__);
    __set_PSP((uint32_t)&__stack_process_end__);
    __set_CONTROL(0);

#if defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3)
    __set_MSPLIM(__STACKSIZE__);
    __set_PSPLIM(__STACKSIZE_PROCESS__);
#endif

    uint32_t *src = &__data_load_start__;
    uint32_t *dst = &__data_start__;
    while(dst < &__data_end__) {
        *dst++ = *src++;
    }
#if defined(DEBUG)
    src = &__text_load_start__;
    dst = &__text_start__;
    while(dst < &__text_end__) {
        if (dst == src) {
            break;
        }
        *dst++ = *src++;
    }
#endif
    src = &__fast_load_start__;
    dst = &__fast_start__;
    while(dst < &__fast_end__) {
        *dst++ = *src++;
    }
    src = &__ctors_load_start__;
    dst = &__ctors_start__;
    while(dst < &__ctors_end__) {
        *dst++ = *src++;
    }
    src = &__dtors_load_start__;
    dst = &__dtors_start__;
    while(dst < &__dtors_end__) {
        *dst++ = *src++;
    }
#if defined(DEBUG)
    src = &__rodata_load_start__;
    dst = &__rodata_start__;
    while(dst < &__rodata_end__) {
        if (dst == src) {
            break;
        }
        *dst++ = *src++;
    }
#endif
    src = &__tdata_load_start__;
    dst = &__tdata_start__;
    while(dst < &__tdata_end__) {
        if (dst == src) {
            *dst++ = *src++;
        }
    }

    // Zeroing bss data
    src = &__bss_start__;
    while(src < &__bss_end__) {
        *src++ = 0;
    }
    src = &__tbss_start__;
    while(src < &__tbss_end__) {
        *src++ = 0;
    }

    src = &__shared_data_start__;
    while(src < &__shared_data_end__) {
        *src++ = 0;
    }

    // Calling constructors
    typedef void (*ctor_func_t)(void);
    ctor_func_t func = (ctor_func_t)&__ctors_start__;
    while(&func < (ctor_func_t *)&__ctors_end__) {
        func++();
    }

    SystemInit();

    hfclk_init();
    lfclk_init();

    // Disable all DCDC regulators (use LDO)
    NRF_REGULATORS_S->VREGRADIO.DCDCEN = (REGULATORS_VREGRADIO_DCDCEN_DCDCEN_Disabled << REGULATORS_VREGRADIO_DCDCEN_DCDCEN_Pos);
    NRF_REGULATORS_S->VREGMAIN.DCDCEN  = (REGULATORS_VREGMAIN_DCDCEN_DCDCEN_Disabled << REGULATORS_VREGMAIN_DCDCEN_DCDCEN_Pos);
    NRF_REGULATORS_S->VREGH.DCDCEN     = (REGULATORS_VREGH_DCDCEN_DCDCEN_Disabled << REGULATORS_VREGH_DCDCEN_DCDCEN_Pos);

    main();
}

// Exception handlers
//
// The trampolines resolve the faulting context's stack frame and pass it in R0
// plus EXC_RETURN in R1. EXC_RETURN bit 6 (S) tells whether the background was
// secure: when a non-secure access faults into the secure handler the frame
// lives on the non-secure stack, so we must read MSP_NS/PSP_NS instead of the
// banked secure SP - otherwise the captured PC reads off the wrong stack as 0.
void HardFault_Handler(void) {
    __ASM(
         "tst    LR, #0x40          ;"  // EXC_RETURN bit 6 (S): secure background?
         "bne    1f                 ;"
         "tst    LR, #4             ;"  // non-secure background: pick NS stack
         "ite    EQ                 ;"
         "mrseq  R0, MSP_NS         ;"
         "mrsne  R0, PSP_NS         ;"
         "b      2f                 ;"
         "1:                        ;"
         "tst    LR, #4             ;"  // secure background: pick secure stack
         "ite    EQ                 ;"
         "mrseq  R0, MSP            ;"
         "mrsne  R0, PSP            ;"
         "2:                        ;"
         "mov    R1, LR             ;"  // EXC_RETURN passed through R1.
         "b      HardFaultHandler   ;"  // Stack frame passed through R0.
    );
}

void SecureFault_Handler(void) {
    __ASM(
         "tst    LR, #0x40          ;"  // EXC_RETURN bit 6 (S): secure background?
         "bne    1f                 ;"
         "tst    LR, #4             ;"  // non-secure background: pick NS stack
         "ite    EQ                 ;"
         "mrseq  R0, MSP_NS         ;"
         "mrsne  R0, PSP_NS         ;"
         "b      2f                 ;"
         "1:                        ;"
         "tst    LR, #4             ;"  // secure background: pick secure stack
         "ite    EQ                 ;"
         "mrseq  R0, MSP            ;"
         "mrsne  R0, PSP            ;"
         "2:                        ;"
         "mov    R1, LR             ;"  // EXC_RETURN passed through R1.
         "b      SecureFaultHandler ;"  // Stack frame passed through R0.
    );
}

void Dummy_Handler(void) {
   while(1) {
       __NOP();
   }
}
