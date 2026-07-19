/**
 * @file
 * @defgroup project_nrf5340_net_core   nRF5340 network core
 * @ingroup projects
 * @brief This application is used to control the radio and rng peripherals and to interact with the application core
 *
 * @author Alexandre Abadie <alexandre.abadie@inria.fr>
 * @copyright Inria, 2023
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <nrf.h>
// Include BSP headers
#include "ipc.h"
#include "nvmc.h"
#include "protocol.h"
#include "rng.h"
#include "sha256.h"
#include "mr_gpio.h"

// Mira includes
#include "mr_timer_hf.h"
#include "mr_radio.h"
#include "models.h"
#include "mac.h"
#include "mari.h"

#define NETCORE_MAIN_TIMER                  (0)

#define SWARMIT_NET_CONFIG_START_ADDRESS    (0x0103f800) // start of the last page (2KB) of the flash (0x01000000 + 0x00040000 - 0x800)
#define SWARMIT_NET_CONFIG_PAGE             (127)       // page index for config (last page)
#define SWARMIT_CONFIG_MAGIC_VALUE          (0x5753524D) // "SWRM" - matches mari + dotbot-provision
// Important: select a Network ID according to the specific deployment you are making,
// see the registry at https://crystalfree.atlassian.net/wiki/spaces/Mari/pages/3324903426/Registry+of+Mari+Network+IDs
#define SWARMIT_DEFAULT_NET_ID              (0xA000)
#define LH2_BASESTATION_COUNT_MAX           (16)

//=========================== variables =========================================

typedef struct __attribute__((packed)) {
    uint32_t magic;                                         ///< must equal SWARMIT_CONFIG_MAGIC_VALUE if the page is valid
    uint32_t has_net_id;                                    ///< 1 if net_id is provisioned; otherwise fall back to SWARMIT_DEFAULT_NET_ID
    uint32_t net_id;                                        ///< Mari network ID, meaningful only when has_net_id == 1
    uint32_t homography_count;                              ///< number of LH2 homography matrices (0 if no calibration baked in)
    int32_t  homographies[LH2_BASESTATION_COUNT_MAX][3][3]; ///< homography matrices for localization
} swarmit_config_t;

typedef struct {
    bool        req_received;
    bool        data_received;
    bool        send_status;
    uint8_t     req_buffer[255];
    uint8_t     notification_buffer[255];
    ipc_req_t   ipc_req;
    bool        ipc_log_received;
    uint8_t     gpio_event_idx;
    crypto_sha256_ctx_t sha256_ctx;
    uint8_t     expected_hash[SWRMT_OTA_SHA256_LENGTH];
    uint8_t     computed_hash[SWRMT_OTA_SHA256_LENGTH];
    uint64_t    device_id;
    uint16_t    mari_net_id;
    bool        mari_initialized;
    int32_t     last_chunk_acked;
    uint32_t    metrics_rx_counter;
    uint32_t    metrics_tx_counter;
    bool        metrics_received;
    swarmit_config_t config;
    bool        lh2_calibration_ready;
} swrmt_app_data_t;

static swrmt_app_data_t _app_vars = { 0 };
extern schedule_t schedule_minuscule, schedule_tiny, schedule_small, schedule_huge, schedule_only_beacons, schedule_only_beacons_optimized_scan;

volatile __attribute__((section(".shared_data"))) ipc_shared_data_t ipc_shared_data;

static const mr_gpio_t _debug1 = { .port = 1, .pin = 8 };
//static const mr_gpio_t _debug2 = { .port = 1, .pin = 10 };

// Mari TX configs. MARI_TX_INTERNAL is exported from models.h for mari's
// own metrics-probe sends.
static const mari_tx_config_t SWARMIT_TX_DEFAULT = {
    .next_proto = MARI_NEXT_PROTO_SWARMIT_TESTBED,
};
static const mari_tx_config_t SWARMIT_TX_DOTBOT_FORWARD = {
    .next_proto = MARI_NEXT_PROTO_DOTBOT_APP,
};

//=========================== functions =========================================

static void _handle_packet(uint64_t dst_address, uint8_t *packet, uint8_t length) {
    memcpy(_app_vars.req_buffer, packet, length);
    uint8_t *ptr = _app_vars.req_buffer;
    uint8_t packet_type = (uint8_t)*ptr++;

    if (length == sizeof(mr_metrics_payload_t) && packet_type == MARI_PAYLOAD_TYPE_METRICS_PROBE) {
        _app_vars.metrics_received = true;
        return;
    }

    if (((packet_type >= SWRMT_MSG_STATUS) && (packet_type <= SWRMT_MSG_OTA_CHUNK)) || (packet_type == SWRMT_MSG_LH2_CALIBRATION) || (packet_type == SWRMT_MSG_LH2_CAPTURE) ||
        (packet_type == SWRMT_MSG_OTA_BLOCK_REPORT_REQ) || (packet_type == SWRMT_MSG_OTA_FINALIZE)) {
        _app_vars.req_received = true;
        return;
    }

    // ignore other types of packet if not in running mode
    if (ipc_shared_data.status != SWRMT_APPLICATION_RUNNING) {
        return;
    }

    if (dst_address != MARI_BROADCAST_ADDRESS && dst_address != _app_vars.device_id) {
        return;
    }

    mutex_lock();
    ipc_shared_data.rx_pdu.length = length;
    memcpy((uint8_t *)ipc_shared_data.rx_pdu.buffer, packet, length);
    mutex_unlock();
    _app_vars.data_received = true;
}

static void mari_event_callback(mr_event_t event, mr_event_data_t event_data) {
    switch (event) {
        case MARI_NEW_PACKET:
        {
            _handle_packet(event_data.data.new_packet.header->dst, event_data.data.new_packet.payload, event_data.data.new_packet.payload_len);
            break;
        }
        case MARI_CONNECTED: {
            uint64_t gateway_id = event_data.data.gateway_info.gateway_id;
            printf("Connected to gateway %016llX\n", gateway_id);
            break;
        }
        case MARI_DISCONNECTED: {
            uint64_t gateway_id = event_data.data.gateway_info.gateway_id;
            printf("Disconnected from gateway %016llX, reason: %u\n", gateway_id, event_data.tag);
            break;
        }
        case MARI_ERROR:
            printf("Error\n");
            break;
        default:
            break;
    }
}

static void _load_config(void) {
    // load config into RAM. On virgin flash every field reads back as 0xFFFFFFFFu.
    // magic gates the whole page; has_net_id and homography_count gate their
    // respective fields independently, so an OTA-calibrated-but-never-provisioned
    // device sees a valid page with only calibration populated (has_net_id stays
    // 0xFFFFFFFFu via the round-trip, so we still fall back to the default net_id).
    const swarmit_config_t *cfg_flash = (const swarmit_config_t *)SWARMIT_NET_CONFIG_START_ADDRESS;
    memcpy(&_app_vars.config, cfg_flash, sizeof(_app_vars.config));

    // set network ID
    if (cfg_flash->magic == SWARMIT_CONFIG_MAGIC_VALUE && cfg_flash->has_net_id == 1) {
        _app_vars.mari_net_id = (uint16_t)(_app_vars.config.net_id & 0xFFFFu);
    } else {
        _app_vars.mari_net_id = SWARMIT_DEFAULT_NET_ID;
    }

    // set lighthouse calibration data (only trust the matrix bytes if magic gates the whole page)
    if (cfg_flash->magic == SWARMIT_CONFIG_MAGIC_VALUE
        && _app_vars.config.homography_count > 0
        && _app_vars.config.homography_count <= LH2_BASESTATION_COUNT_MAX) {
        // copy homography matrices to shared memory without casting away volatile
        for (uint32_t idx = 0; idx < _app_vars.config.homography_count; idx++) {
            for (uint32_t row = 0; row < 3; row++) {
                for (uint32_t col = 0; col < 3; col++) {
                    ipc_shared_data.lh2_calibration.homographies[idx][row][col] =
                        _app_vars.config.homographies[idx][row][col];
                }
            }
        }
        ipc_shared_data.lh2_calibration.homography_count = _app_vars.config.homography_count;
        _app_vars.lh2_calibration_ready = true;
    }
}

uint64_t _deviceid(void) {
    return ((uint64_t)NRF_FICR_NS->INFO.DEVICEID[1]) << 32 | (uint64_t)NRF_FICR_NS->INFO.DEVICEID[0];
}

static void _send_status(void) {
    _app_vars.send_status = true;
}

static void _commit_config_and_reboot(void) {
    mr_gpio_set(&_debug1); mr_gpio_clear(&_debug1);

    // Always stamp the magic before write — a device that was never provisioned
    // via dotbot-provision (page is virgin 0xFF...) and is committing config
    // for the first time via OTA would otherwise persist 0xFFFFFFFFu as magic
    // and self-invalidate on next boot.
    _app_vars.config.magic = SWARMIT_CONFIG_MAGIC_VALUE;

    mr_gpio_set(&_debug1);
    nvmc_page_erase(SWARMIT_NET_CONFIG_PAGE);
    mr_gpio_clear(&_debug1);
    mr_gpio_set(&_debug1);
    nvmc_write((const uint32_t *)SWARMIT_NET_CONFIG_START_ADDRESS, &_app_vars.config, sizeof(_app_vars.config));
    mr_gpio_clear(&_debug1);

    // Ask the application core to perform a system-wide reset. App-core
    // NVIC_SystemReset is a system reset on nRF5340 — both cores come back
    // up fresh, picking up the new calibration on boot. A net-core-local
    // NVIC_SystemReset would only reset this domain and leave the app core
    // with stale Mari / localization state.
    puts("Calibration/config committed to flash, requesting system reset");
    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_SOC_RESET] = 1;
    while (1) { __WFE(); }
}

//=========================== main ==============================================

int main(void) {
    _app_vars.device_id = _deviceid();
    _load_config();

    NRF_IPC_NS->INTENSET                             = (1 << IPC_CHAN_REQ) | (1 << IPC_CHAN_LOG_EVENT);
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_RADIO_RX]          = 1 << IPC_CHAN_RADIO_RX;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_APPLICATION_START] = 1 << IPC_CHAN_APPLICATION_START;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_APPLICATION_STOP]  = 1 << IPC_CHAN_APPLICATION_STOP;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_SOC_RESET]         = 1 << IPC_CHAN_SOC_RESET;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_OTA_START]         = 1 << IPC_CHAN_OTA_START;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_OTA_CHUNK]         = 1 << IPC_CHAN_OTA_CHUNK;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_OTA_FINALIZE]      = 1 << IPC_CHAN_OTA_FINALIZE;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_CALIBRATION_DATA]  = 1 << IPC_CHAN_CALIBRATION_DATA;
    NRF_IPC_NS->SEND_CNF[IPC_CHAN_LH2_CAPTURE]       = 1 << IPC_CHAN_LH2_CAPTURE;
    NRF_IPC_NS->RECEIVE_CNF[IPC_CHAN_REQ]            = 1 << IPC_CHAN_REQ;
    NRF_IPC_NS->RECEIVE_CNF[IPC_CHAN_LOG_EVENT]      = 1 << IPC_CHAN_LOG_EVENT;

    NVIC_EnableIRQ(IPC_IRQn);
    NVIC_ClearPendingIRQ(IPC_IRQn);
    NVIC_SetPriority(IPC_IRQn, 1);

    // Configure timer used for timestamping events
    mr_timer_hf_init(NETCORE_MAIN_TIMER);
    mr_timer_hf_set_periodic_us(NETCORE_MAIN_TIMER, 0, 1000000UL, _send_status);

    mr_gpio_init(&_debug1, MR_GPIO_OUT);
    // mr_gpio_init(&_debug2, MR_GPIO_OUT);

    mr_gpio_set(&_debug1); mr_gpio_clear(&_debug1);
    // mr_gpio_set(&_debug2); mr_gpio_clear(&_debug2);

    // Network core must remain on
    ipc_shared_data.net_ready = true;

    while (1) {
        __WFE();

        if (_app_vars.lh2_calibration_ready) {
            _app_vars.lh2_calibration_ready = false;
            NRF_IPC_NS->TASKS_SEND[IPC_CHAN_CALIBRATION_DATA] = 1;
        }

        if (_app_vars.send_status) {
            _app_vars.send_status = false;
            size_t length = 0;
            _app_vars.notification_buffer[length++] = SWRMT_MSG_STATUS;
            _app_vars.notification_buffer[length++] = ipc_shared_data.device_type;
            _app_vars.notification_buffer[length++] = ipc_shared_data.status;
            memcpy(&_app_vars.notification_buffer[length], (void *)&ipc_shared_data.battery_level, sizeof(uint16_t));
            length += sizeof(uint16_t);
            memcpy(&_app_vars.notification_buffer[length], (void *)&ipc_shared_data.current_position, sizeof(position_2d_t));
            length += sizeof(position_2d_t);
            memcpy(&_app_vars.notification_buffer[length], (void *)&ipc_shared_data.crash_report, sizeof(ipc_crash_report_t));
            length += sizeof(ipc_crash_report_t);
            mari_node_tx_payload(_app_vars.notification_buffer, length, &SWARMIT_TX_DEFAULT);
        }

        if (_app_vars.req_received) {
            _app_vars.req_received = false;
            swrmt_request_t *req = (swrmt_request_t *)_app_vars.req_buffer;
            switch (req->type) {
                case SWRMT_MSG_START:
                    if (ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }
                    puts("Start request received");
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_APPLICATION_START] = 1;
                    break;
                case SWRMT_MSG_STOP:
                    if ((ipc_shared_data.status != SWRMT_APPLICATION_RUNNING) && (ipc_shared_data.status != SWRMT_APPLICATION_RESETTING) && (ipc_shared_data.status != SWRMT_APPLICATION_PROGRAMMING)) {
                        break;
                    }
                    puts("Stop request received");
                    ipc_shared_data.status = SWRMT_APPLICATION_STOPPING;
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_APPLICATION_STOP] = 1;
                    break;
                case SWRMT_MSG_RESET:
                    if (ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }
                    memcpy((uint8_t *)&ipc_shared_data.target_position, req->data, sizeof(position_2d_t));
                    puts("Reset request received");
                    ipc_shared_data.status = SWRMT_APPLICATION_RESETTING;
                    //NRF_IPC_NS->TASKS_SEND[IPC_CHAN_SOC_RESET] = 1;
                    break;
                case SWRMT_MSG_OTA_START:
                {
                    if (ipc_shared_data.status != SWRMT_APPLICATION_READY && ipc_shared_data.status != SWRMT_APPLICATION_PROGRAMMING) {
                        break;
                    }
                    ipc_shared_data.ota.last_chunk_acked = -1;
                    ipc_shared_data.status = SWRMT_APPLICATION_PROGRAMMING;
                    const swrmt_ota_start_pkt_t *pkt = (const swrmt_ota_start_pkt_t *)req->data;
                    // Erase the corresponding flash pages.
                    mutex_lock();
                    ipc_shared_data.ota.image_size = pkt->image_size;
                    ipc_shared_data.ota.chunk_count = pkt->chunk_count;
                    // Protocol version tells the bootloader block (>=2) vs legacy:
                    // in block mode it must NOT send a per-chunk ack (that uplink
                    // frame per chunk throttles the transfer to the uplink rate).
                    ipc_shared_data.ota.protocol_version = pkt->version;
                    // Reset the block-OTA bitmap state for the new image.
                    ipc_shared_data.ota.block_index = 0;
                    ipc_shared_data.ota.received_mask = 0;
                    ipc_shared_data.ota.finalize_ok = 0;
                    mutex_unlock();
                    printf("OTA Start request received (size: %u, chunks: %u)\n", ipc_shared_data.ota.image_size, ipc_shared_data.ota.chunk_count);
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_OTA_START] = 1;
                } break;
                case SWRMT_MSG_OTA_CHUNK:
                {
                    if (ipc_shared_data.status != SWRMT_APPLICATION_PROGRAMMING && ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }

                    const swrmt_ota_chunk_pkt_t *pkt = (const swrmt_ota_chunk_pkt_t *)req->data;
                    uint32_t index = pkt->index;

                    // Check chunk index is valid
                    if (index >= ipc_shared_data.ota.chunk_count) {
                        break;
                    }

                    // Only verify + publish if the chunk was not already handled.
                    if (ipc_shared_data.ota.last_chunk_acked != (int32_t)index) {
                        // Verify the chunk SHA on the wire buffer (our own req
                        // buffer) BEFORE publishing it to the shared IPC buffer -
                        // no lock needed for the verify.
                        crypto_sha256_init(&_app_vars.sha256_ctx);
                        crypto_sha256_update(&_app_vars.sha256_ctx, (const uint8_t *)pkt->chunk, pkt->chunk_size);
                        crypto_sha256(&_app_vars.sha256_ctx, _app_vars.computed_hash);
                        if (memcmp(_app_vars.computed_hash, pkt->sha, 8) != 0) {
                            break;
                        }
                        // Publish index + size + data together under the mutex so
                        // the bootloader can never read a torn chunk.
                        mutex_lock();
                        ipc_shared_data.ota.chunk_index = index;
                        ipc_shared_data.ota.chunk_size = pkt->chunk_size;
                        memcpy((uint8_t *)ipc_shared_data.ota.chunk, pkt->chunk, pkt->chunk_size);
                        mutex_unlock();
                    } else {
                        // Duplicate of the last chunk: republish the index so the
                        // bootloader can re-set the mask bit (idempotent).
                        mutex_lock();
                        ipc_shared_data.ota.chunk_index = index;
                        mutex_unlock();
                    }
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_OTA_CHUNK] = 1;
                } break;
                case SWRMT_MSG_OTA_BLOCK_REPORT_REQ:
                {
                    // Reply with the received-chunk bitmap for the block this
                    // bot currently holds. The bootloader owns the bitmap (it
                    // sets bits as it writes flash); the net core just reads the
                    // shared copy and answers in the bot's own uplink slot, no
                    // IPC round trip. A bot that has not started the requested
                    // block reports an earlier block_index, which the controller
                    // reads as "needs the whole block".
                    size_t length = 0;
                    _app_vars.notification_buffer[length++] = SWRMT_MSG_OTA_BLOCK_REPORT_RESP;
                    mutex_lock();
                    uint32_t block_index = ipc_shared_data.ota.block_index;
                    uint32_t received_mask = ipc_shared_data.ota.received_mask;
                    mutex_unlock();
                    memcpy(&_app_vars.notification_buffer[length], &block_index, sizeof(uint32_t));
                    length += sizeof(uint32_t);
                    memcpy(&_app_vars.notification_buffer[length], &received_mask, sizeof(uint32_t));
                    length += sizeof(uint32_t);
                    _app_vars.notification_buffer[length++] = 0;  // status (reserved)
                    mari_node_tx_payload(_app_vars.notification_buffer, length, &SWARMIT_TX_DEFAULT);
                } break;
                case SWRMT_MSG_OTA_FINALIZE:
                {
                    if (ipc_shared_data.status != SWRMT_APPLICATION_PROGRAMMING && ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }
                    // Hand the expected whole-image SHA256 to the app core; it
                    // reads back its own flash, compares, and sends the
                    // FINALIZE_RESP itself (it owns the flash and the mari TX
                    // shim, mirroring the chunk-ack path).
                    const swrmt_ota_finalize_pkt_t *pkt = (const swrmt_ota_finalize_pkt_t *)req->data;
                    mutex_lock();
                    memcpy((uint8_t *)ipc_shared_data.ota.finalize_expected, pkt->sha, SWRMT_OTA_SHA256_LENGTH);
                    mutex_unlock();
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_OTA_FINALIZE] = 1;
                } break;
                case SWRMT_MSG_LH2_CALIBRATION:
                {
                    // mr_gpio_set(&_debug1);
                    if (ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }

                    const swrmt_lh2_calibration_data_t *pkt = (const swrmt_lh2_calibration_data_t *)req->data;
                    if (pkt->homography_index >= LH2_BASESTATION_COUNT_MAX) {
                        // printf("Invalid calibration index %u\n", pkt->homography_index);
                        break;
                    }
                    if (pkt->homography_count == 0 || pkt->homography_count > LH2_BASESTATION_COUNT_MAX) {
                        // printf("Invalid calibration count %u\n", pkt->homography_count);
                        break;
                    }
                    if (pkt->homography_index >= pkt->homography_count) {
                        // printf("Invalid calibration tuple (idx=%u, count=%u)\n",
                        //        pkt->homography_index,
                        //        pkt->homography_count);
                        break;
                    }

                    /* Keep receiving matrices in RAM and commit once on the last index.
                       On the first packet of a new calibration session, zero the
                       array so any unrecovered slot from the previous session
                       does not silently survive into the flash commit. */
                    if (pkt->homography_index == 0) {
                        memset(_app_vars.config.homographies, 0, sizeof(_app_vars.config.homographies));
                    }
                    _app_vars.config.homography_count = pkt->homography_count;
                    memcpy(_app_vars.config.homographies[pkt->homography_index], pkt->homography, sizeof(_app_vars.config.homographies[0]));

                    // printf(
                    //     "Calibration matrix received (count: %u, index: %u)\n",
                    //     pkt->homography_count,
                    //     pkt->homography_index
                    // );

                    // mr_gpio_set(&_debug1);

                    /* User-defined protocol: last matrix index triggers flash commit + reboot. */
                    if (pkt->homography_index == (pkt->homography_count - 1)) {
                        _commit_config_and_reboot();
                    }
                } break;
                case SWRMT_MSG_LH2_CAPTURE:
                    // Raw LH2 capture only makes sense while the secure bootloader owns
                    // the main loop (READY). In RUNNING the secure side has jumped to the
                    // non-secure image and never services this channel.
                    if (ipc_shared_data.status != SWRMT_APPLICATION_READY) {
                        break;
                    }
                    NRF_IPC_NS->TASKS_SEND[IPC_CHAN_LH2_CAPTURE] = 1;
                    break;
                default:
                    break;
            }
        }

        if (_app_vars.ipc_req != IPC_REQ_NONE) {
            ipc_shared_data.net_ack = false;
            switch (_app_vars.ipc_req) {
                // Mira node functions
                case IPC_MARI_INIT_REQ:
                    if (!_app_vars.mari_initialized) {
                        mari_init(MARI_NODE, _app_vars.mari_net_id, &schedule_tiny, &mari_event_callback);
                        _app_vars.mari_initialized = true;
                    }
                    break;
                case IPC_MARI_NODE_TX_REQ: {
                    while (!mari_node_is_connected()) {}
                    // forward user-image data as DOTBOT_APP, but keep the bootloader's
                    // messages when user image is not running
                    bool user_running = (ipc_shared_data.status == SWRMT_APPLICATION_RUNNING ||
                                         ipc_shared_data.status == SWRMT_APPLICATION_STOPPING);
                    const mari_tx_config_t *tx_config = user_running ? &SWARMIT_TX_DOTBOT_FORWARD : &SWARMIT_TX_DEFAULT;
                    mari_node_tx_payload((uint8_t *)ipc_shared_data.tx_pdu.buffer, ipc_shared_data.tx_pdu.length, tx_config);
                    break;
                }
                case IPC_RNG_INIT_REQ:
                    db_rng_init();
                    break;
                case IPC_RNG_READ_REQ:
                    db_rng_read((uint8_t *)&ipc_shared_data.rng.value);
                    break;
                default:
                    break;
            }
            ipc_shared_data.net_ack = true;
            _app_vars.ipc_req      = IPC_REQ_NONE;
        }

        if (_app_vars.data_received) {
            _app_vars.data_received = false;
            NRF_IPC_NS->TASKS_SEND[IPC_CHAN_RADIO_RX] = 1;
        }

        if (_app_vars.metrics_received) {
            _app_vars.metrics_received = false;
            mr_metrics_payload_t *metrics_payload = (mr_metrics_payload_t *)_app_vars.req_buffer;
            // update metrics probe
            metrics_payload->node_rx_count        = ++_app_vars.metrics_rx_counter;
            metrics_payload->node_rx_asn          = mr_mac_get_asn();
            metrics_payload->node_tx_count        = ++_app_vars.metrics_tx_counter;
            metrics_payload->node_tx_enqueued_asn = mr_mac_get_asn();
            metrics_payload->rssi_at_node         = mr_radio_rssi();

            // send metrics probe to gateway
            mari_node_tx_payload((uint8_t *)metrics_payload, sizeof(mr_metrics_payload_t), &MARI_TX_INTERNAL);
        }

        if (_app_vars.ipc_log_received) {
            _app_vars.ipc_log_received = false;
            // Notify log data
            size_t length = 0;
            _app_vars.notification_buffer[length++] = SWRMT_MSG_LOG_EVENT;
            uint32_t timestamp = mr_timer_hf_now(NETCORE_MAIN_TIMER);
            memcpy(_app_vars.notification_buffer + length, &timestamp, sizeof(uint32_t));
            length += sizeof(uint32_t);
            mutex_lock();
            memcpy(_app_vars.notification_buffer + length, (void *)&ipc_shared_data.log, ipc_shared_data.log.length + 1);
            mutex_unlock();
            length += ipc_shared_data.log.length + 1;
            mari_node_tx_payload(_app_vars.notification_buffer, length, &SWARMIT_TX_DEFAULT);
        }
    }
}

void IPC_IRQHandler(void) {
    if (NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_REQ]) {
        NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_REQ] = 0;
        _app_vars.ipc_req                        = ipc_shared_data.req;
    }

    if (NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_LOG_EVENT]) {
        NRF_IPC_NS->EVENTS_RECEIVE[IPC_CHAN_LOG_EVENT] = 0;
        _app_vars.ipc_log_received                     = true;
    }
}
