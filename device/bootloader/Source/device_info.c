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
#define DEVICE_RECORD_VERSION   (2U)

/// The page holds an array of fixed-size slots rather than one record at a
/// fixed address, and each write appends to the next free slot. Only when the
/// last slot is used does the page get erased.
///
/// This is what makes the wear acceptable. Rewriting one record in place costs
/// an erase per boot, and an experiment start and an experiment stop are each a
/// boot, so the page wears at the rate the testbed is *used*: at 40 boots a day
/// the 10k erase endurance (nRF5340 PS v1.6, nENDURANCE) is spent in eight
/// months. Appending divides that by the slot count, which puts it past twenty
/// years at the same rate.
///
/// It also makes the update atomic, which rewriting in place is not: the magic
/// word is written last, so a power cut mid-write leaves the new slot's magic
/// erased and therefore invalid, and the previous slot is still the newest
/// valid one. Rewriting in place has an ~88 ms window (tERASEPAGE) where a
/// power cut destroys the record outright.
#define DEVICE_RECORD_SLOT_SIZE (128U)
#define DEVICE_RECORD_SLOTS     (FLASH_PAGE_SIZE / DEVICE_RECORD_SLOT_SIZE)

//=========================== variables ========================================

/// Persisted verbatim in a slot of DEVICE_RECORD_PAGE. Packed and word-sized so
/// the NVMC word writes land where this layout says they do.
typedef struct __attribute__((packed)) {
    /// Written LAST and checked FIRST, which is what makes an append atomic:
    /// a slot whose body landed but whose magic did not reads as erased.
    uint32_t magic;
    uint32_t record_version;
    uint32_t boot_count;
    /// Monotonic across boots AND events, which is why it is stored rather
    /// than derived from boot_count. Deriving it collides with its own
    /// increment: a boot that finalizes one OTA ends on boot_count+1, which is
    /// exactly what the next boot would start from, so the host sees no change
    /// across the reset and never refetches. `swarm flash` followed by `swarm
    /// start` is that sequence, and start resets.
    uint32_t info_gen;
    uint32_t image_size;
    uint8_t  image_sha256[SWRMT_OTA_SHA256_LENGTH];
    char     image_name[SWRMT_INFO_STRING_LEN];
    char     image_version[SWRMT_INFO_STRING_LEN];
    /// Pads the record out to the slot size. Adding a field here costs no
    /// change to the slot layout, and therefore no migration.
    uint8_t  reserved[12];
} swrmt_device_record_t;

// NVMC writes whole 32-bit words and faults on an unaligned access, so the
// record has to be a whole number of words, and exactly one slot so the slot
// index is all the addressing needed.
_Static_assert(sizeof(swrmt_device_record_t) % 4 == 0,
               "device record must be a whole number of 32-bit words");
_Static_assert(sizeof(swrmt_device_record_t) == DEVICE_RECORD_SLOT_SIZE,
               "device record must fill exactly one slot");
_Static_assert(DEVICE_RECORD_SLOTS * DEVICE_RECORD_SLOT_SIZE <= FLASH_PAGE_SIZE,
               "the slots must fit in the reserved page");

extern volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static swrmt_device_record_t _record = { 0 };

/// Slot holding the newest valid record; -1 when the page has none.
static int32_t _slot_index = -1;

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

static const swrmt_device_record_t *_slot_at(uint32_t index) {
    return (const swrmt_device_record_t *)(DEVICE_RECORD_ADDRESS +
                                           index * DEVICE_RECORD_SLOT_SIZE);
}

/// Highest slot index holding a valid record, or -1 if the page holds none.
///
/// Highest rather than a sequence-number search because writes only ever move
/// forward through the page and the page is erased whole, so the last valid
/// slot is by construction the newest.
static int32_t _find_newest_slot(void) {
    int32_t newest = -1;
    for (uint32_t i = 0; i < DEVICE_RECORD_SLOTS; i++) {
        const swrmt_device_record_t *slot = _slot_at(i);
        if (slot->magic == DEVICE_RECORD_MAGIC &&
            slot->record_version == DEVICE_RECORD_VERSION) {
            newest = (int32_t)i;
        }
    }
    return newest;
}

/// Append the in-RAM record to the next free slot, erasing only when full.
static void _record_persist(void) {

    if (_slot_index < 0 || _slot_index + 1 >= (int32_t)DEVICE_RECORD_SLOTS) {
        // Nothing usable in the page, or the last slot is taken. Erasing when
        // nothing is valid also covers a page holding garbage, which cannot be
        // written into without an erase first.
        nvmc_page_erase_secure(DEVICE_RECORD_PAGE);
        _slot_index = 0;
    } else {
        _slot_index++;
    }

    const uint32_t base = DEVICE_RECORD_ADDRESS + (uint32_t)_slot_index * DEVICE_RECORD_SLOT_SIZE;
    const uint8_t *bytes = (const uint8_t *)&_record;

    // Body first, magic last. Both halves are word-aligned and word-sized, and
    // the ordering is the atomicity: a power cut between them leaves a slot
    // whose magic is still erased, so the next boot ignores it and keeps
    // reading the previous slot.
    nvmc_write_secure((const uint32_t *)(base + sizeof(uint32_t)),
                      bytes + sizeof(uint32_t),
                      sizeof(_record) - sizeof(uint32_t));
    __DSB();
    nvmc_write_secure((const uint32_t *)base, bytes, sizeof(uint32_t));
}

/// Advance the persisted generation counter and publish it, after every field
/// it describes is already in shared memory.
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
    _record.info_gen++;
    // Zero is reserved on the wire. A host recognises firmware that predates
    // this message by a status frame too short to carry the counter, which it
    // zero-fills - so a real device must never report 0, or it would be
    // mistaken for one that cannot answer. Skipping the value costs one
    // increment every 256 boots and keeps that discriminator exact.
    if ((uint8_t)_record.info_gen == 0) {
        _record.info_gen++;
    }
    _record_persist();
    __DMB();
    ipc_shared_data.device_info.info_gen = (uint8_t)_record.info_gen;
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

void device_info_init(void) {

    _slot_index = _find_newest_slot();

    if (_slot_index >= 0) {
        memcpy(&_record, _slot_at((uint32_t)_slot_index), sizeof(_record));
    } else {
        // Virgin flash reads back as all 0xFF, and so does a record written by
        // a future schema we cannot interpret. Either way, start clean rather
        // than reporting 0xFFFFFFFF reboots and a garbage image name.
        memset(&_record, 0, sizeof(_record));
        _record.magic = DEVICE_RECORD_MAGIC;
        _record.record_version = DEVICE_RECORD_VERSION;
    }

    _record.boot_count++;
    // Until boot-time verification lands, the record is trusted as written:
    // it was only ever stored after a whole-image SHA256 match.
    ipc_shared_data.device_info.image_state = SWRMT_IMAGE_STATE_IDLE;
    ipc_shared_data.device_info.image_result =
        (_record.image_size > 0) ? SWRMT_IMAGE_RESULT_SUCCESS : SWRMT_IMAGE_RESULT_INITIAL;
    _publish();
    // Advances and persists the counter, so this boot presents a value no
    // previous boot or event has used. Also writes the bumped boot_count,
    // which is why there is no separate persist above.
    _bump_generation();
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

    ipc_shared_data.device_info.image_state = SWRMT_IMAGE_STATE_IDLE;
    ipc_shared_data.device_info.image_result = SWRMT_IMAGE_RESULT_SUCCESS;
    _publish();
    // Writes the record too, so the new image fields and the counter that
    // advertises them land in the same erase-write rather than two.
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
