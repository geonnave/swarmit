/**
 * @file
 * @brief Flash-backed record of what this bot is running.
 *
 * @copyright Inria, 2026
 */

#include <stdint.h>
#include <string.h>

#include <nrf.h>

#include "device_info.h"
#include "ipc.h"
#include "nvmc.h"
#include "protocol.h"
#include "version.h"

//=========================== defines ==========================================

/// Page 14 of the application core flash. It sits inside the secure region
/// (tz_configure_flash_secure(0, 4) covers 0x0000-0xFFFF) so non-secure user
/// code cannot rewrite what the bot says about itself, and it is reserved in
/// Setup/MemoryMap.xml as DEVICE_META so a bootloader that grows into it fails
/// at link time rather than by corrupting the record at run time.
#define DEVICE_RECORD_PAGE      (14U)
#define DEVICE_RECORD_ADDRESS   (DEVICE_RECORD_PAGE * FLASH_PAGE_SIZE)

/// "SWRM". The same magic the network core's config page and mari's gateway
/// config use. The two records cannot be confused: this one is at a fixed
/// address in application core flash, that one at a fixed address in network
/// core flash, and neither is ever scanned for.
#define DEVICE_RECORD_MAGIC     (0x5753524DUL)
#define DEVICE_RECORD_VERSION   (1U)

/// nRF5340 application core RESETREAS bits this mapping cares about.
#define RR_PIN                  (1UL << 0)
#define RR_WDT0                 (1UL << 1)   ///< crash deadman the running app must pet
#define RR_SREQ                 (1UL << 3)
#define RR_LOCKUP               (1UL << 4)
#define RR_WDT1                 (1UL << 25)  ///< only the stop command starts WDT1

//=========================== variables ========================================

/// Persisted verbatim in DEVICE_RECORD_PAGE. Packed and word-sized so the
/// NVMC word writes land where this layout says they do.
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t record_version;
    uint32_t boot_count;
    uint32_t image_size;
    uint8_t  image_sha256[SWRMT_OTA_SHA256_LENGTH];
    char     image_name[SWRMT_INFO_STRING_LEN];
    char     image_version[SWRMT_INFO_STRING_LEN];
} swrmt_device_record_t;

// NVMC writes whole 32-bit words and faults on an unaligned access, so the
// record has to be a whole number of words.
_Static_assert(sizeof(swrmt_device_record_t) % 4 == 0,
               "device record must be a whole number of 32-bit words");
_Static_assert(sizeof(swrmt_device_record_t) <= FLASH_PAGE_SIZE,
               "device record must fit in its reserved page");

extern volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static swrmt_device_record_t _record = { 0 };

//=========================== private ==========================================

/// Copy a NUL-terminated string into a fixed-width field, truncating rather
/// than overflowing and zeroing the remainder - the host reads these fields as
/// NUL-padded. The two variants differ only in which side is volatile; shared
/// memory cannot be handed to memcpy without casting the qualifier away, and
/// that cast is exactly what these avoid.
static void _copy_string_to_volatile(volatile char *dst, const char *src, size_t cap) {
    size_t i = 0;
    for (; i < cap - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    for (; i < cap; i++) {
        dst[i] = '\0';
    }
}

static void _copy_string_from_volatile(char *dst, const volatile char *src, size_t cap) {
    size_t i = 0;
    for (; i < cap - 1 && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    for (; i < cap; i++) {
        dst[i] = '\0';
    }
}

/// One page erase plus one write. This runs on every boot, and an experiment
/// start and an experiment stop are each a boot, so the page wears at the rate
/// the testbed is used rather than the rate images change: roughly 3.6k cycles
/// a year at ten boots a day, against a 10k endurance spec. That is the cost of
/// having the reboot count survive a power cycle. If boot rates rise enough to
/// matter, the escape is to keep boot_count in .non_init RAM the way
/// crash_latch does and write flash only when the image changes, which trades
/// the power-cycle count for the wear.
static void _record_persist(void) {
    nvmc_page_erase_secure(DEVICE_RECORD_PAGE);
    nvmc_write_secure((const uint32_t *)DEVICE_RECORD_ADDRESS, &_record, sizeof(_record));
}

/// Matter BootReasonEnum (cluster 0x0033 attribute 0x0004) from RESETREAS plus
/// the latched fault. The enum is deliberately coarse - the exact register
/// value and the fault snapshot still travel in the status frame's crash
/// report, which stays the authoritative post-mortem.
static uint8_t _boot_reason(uint32_t resetreas, uint8_t fault) {
    // A crash wins over everything: the fault handler latches and then hangs
    // until WDT0 resets the chip, so both bits can be set at once.
    if (fault || (resetreas & RR_WDT0)) {
        return SWRMT_BOOT_REASON_HW_WATCHDOG;
    }
    if (resetreas & RR_LOCKUP) {
        return SWRMT_BOOT_REASON_HW_WATCHDOG;
    }
    if (resetreas & RR_WDT1) {
        // WDT1 is started by the stop command's DPPI path and by nothing else,
        // so this is a commanded reset rather than a watchdog failure.
        return SWRMT_BOOT_REASON_SW_RESET;
    }
    if (resetreas == 0 || (resetreas & RR_PIN)) {
        return SWRMT_BOOT_REASON_POWER_ON;
    }
    if (resetreas & RR_SREQ) {
        return SWRMT_BOOT_REASON_SW_RESET;
    }
    return SWRMT_BOOT_REASON_UNSPECIFIED;
}

/// Publish the generation counter, and nothing else, after every field it
/// describes is already in shared memory.
///
/// This is the write half of a lock-free handshake with the network core, and
/// the ordering is the whole of it. The reader samples the counter BEFORE the
/// fields and the writer moves it AFTER them, so the two failure modes are not
/// symmetric: a reader that races a commit ships the old counter with new
/// fields, the host caches that old value, the next status frame carries the
/// new one, and the mismatch triggers one more fetch. Bumping the counter
/// first would produce the opposite - the new counter with stale fields, which
/// the host would cache as current and never correct.
static void _bump_generation(void) {
    __DMB();
    ipc_shared_data.device_info.info_gen++;
}

/// Mirror the record plus the build-time version into shared memory.
static void _publish(void) {
    ipc_shared_data.device_info.boot_count = _record.boot_count;
    ipc_shared_data.device_info.image_size = _record.image_size;
    for (size_t i = 0; i < SWRMT_IMAGE_DIGEST_LEN; i++) {
        ipc_shared_data.device_info.image_digest[i] = _record.image_sha256[i];
    }
    _copy_string_to_volatile(ipc_shared_data.device_info.image_name,
                          _record.image_name, SWRMT_INFO_STRING_LEN);
    _copy_string_to_volatile(ipc_shared_data.device_info.image_version,
                          _record.image_version, SWRMT_INFO_STRING_LEN);
    _copy_string_to_volatile(ipc_shared_data.device_info.bl_version,
                          SWRMT_FW_VERSION, SWRMT_INFO_STRING_LEN);
}

//=========================== public ===========================================

void device_info_init(uint32_t resetreas, uint8_t fault) {

    const swrmt_device_record_t *stored = (const swrmt_device_record_t *)DEVICE_RECORD_ADDRESS;

    if (stored->magic == DEVICE_RECORD_MAGIC && stored->record_version == DEVICE_RECORD_VERSION) {
        memcpy(&_record, stored, sizeof(_record));
    } else {
        // Virgin flash reads back as all 0xFF, and so does a record written by
        // a future schema we cannot interpret. Either way, start clean rather
        // than reporting 0xFFFFFFFF reboots and a garbage image name.
        memset(&_record, 0, sizeof(_record));
        _record.magic = DEVICE_RECORD_MAGIC;
        _record.record_version = DEVICE_RECORD_VERSION;
    }

    _record.boot_count++;
    _record_persist();

    // Seed the generation counter from the boot count so a bot that reboots
    // always presents a value the controller has not cached, without needing
    // any state of its own to survive the reset.
    ipc_shared_data.device_info.info_gen = (uint8_t)_record.boot_count;
    ipc_shared_data.device_info.boot_reason = _boot_reason(resetreas, fault);
    // Until boot-time verification lands, the record is trusted as written:
    // it was only ever stored after a whole-image SHA256 match.
    ipc_shared_data.device_info.image_state = SWRMT_IMAGE_STATE_IDLE;
    ipc_shared_data.device_info.image_result =
        (_record.image_size > 0) ? SWRMT_IMAGE_RESULT_SUCCESS : SWRMT_IMAGE_RESULT_INITIAL;
    _publish();
}

void device_info_commit_image(void) {

    _record.image_size = ipc_shared_data.ota.image_size;
    for (size_t i = 0; i < SWRMT_OTA_SHA256_LENGTH; i++) {
        _record.image_sha256[i] = ipc_shared_data.ota.finalize_expected[i];
    }
    // The name and version the controller staged in OTA_START. A controller
    // that sent neither leaves them empty and the host falls back to the
    // digest, which is the identity anyway.
    _copy_string_from_volatile(_record.image_name,
                               ipc_shared_data.ota.pending_name, SWRMT_INFO_STRING_LEN);
    _copy_string_from_volatile(_record.image_version,
                               ipc_shared_data.ota.pending_version, SWRMT_INFO_STRING_LEN);

    _record_persist();

    ipc_shared_data.device_info.image_state = SWRMT_IMAGE_STATE_IDLE;
    ipc_shared_data.device_info.image_result = SWRMT_IMAGE_RESULT_SUCCESS;
    _publish();
    _bump_generation();
}

void device_info_fail_image(uint8_t result) {
    ipc_shared_data.device_info.image_state = SWRMT_IMAGE_STATE_IDLE;
    ipc_shared_data.device_info.image_result = result;
    _bump_generation();
}

void device_info_set_image_state(uint8_t state) {
    ipc_shared_data.device_info.image_state = state;
}
