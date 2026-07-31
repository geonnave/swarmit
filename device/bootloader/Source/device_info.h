#ifndef __DEVICE_INFO_H
#define __DEVICE_INFO_H

/**
 * @file
 * @brief What this bot is running: a flash-backed record of the loaded user
 *        image, published to the network core through shared memory.
 *
 * The record lives in a page of the SECURE region, so non-secure user code
 * cannot forge what the bot reports about itself. It is rewritten at boot to
 * carry the reboot count, and on a verified OTA finalize to describe the image
 * that just landed - never before the whole-image SHA256 has matched, so the
 * record can never describe an image that did not fully arrive.
 */

#include <stdint.h>

/**
 * @brief Load the record, count this boot, and publish the result.
 *
 * Reads the record, bumps its boot count, writes it back, and fills
 * ipc_shared_data.device_info with everything the application core owns. Call
 * once, before the network core is released, so the first status frame already
 * carries a settled generation counter.
 *
 */
void device_info_init(void);

/**
 * @brief Record the image that just passed its whole-image SHA256 check.
 *
 * Promotes the name and version staged by OTA_START plus the verified digest
 * and size into the record, writes it to flash, and bumps the generation
 * counter so the host refetches.
 */
void device_info_commit_image(void);

/**
 * @brief Report that the image transfer failed its integrity check.
 *
 * Leaves the record describing the previous image - it is still what is
 * loaded - and bumps the generation counter so the host sees the failure.
 *
 * @param[in] result  a swrmt_image_result_t value
 */
void device_info_fail_image(uint8_t result);

/**
 * @brief Track the download state machine (LwM2M Object 5 State).
 *
 * Does not bump the generation counter: a transfer in progress would
 * otherwise pull an info fetch per bot into the middle of the flash campaign,
 * and the host driving that campaign already knows the state.
 *
 * @param[in] state  a swrmt_image_state_t value
 */
void device_info_set_image_state(uint8_t state);

#endif
