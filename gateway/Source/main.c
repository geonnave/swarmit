#include <nrf.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "board_config.h"
#include "clock.h"
#include "device.h"
#include "gpio.h"
#include "timer.h"
#include "uart.h"

#include "packet.h"
#include "mira.h"

//=========================== defines ==========================================
#define TIMER_DEV           (1)
#define BUFFER_MAX_BYTES (255U)         ///< Max bytes in UART receive buffer
#define UART_BAUDRATE    (1000000UL)    ///< UART baudrate used by the gateway
#define UART_INDEX       (0)            ///< Index of UART peripheral to use

#define SWARMIT_MIRA_NET_ID 0x0017

#if defined(USE_MIRA_SCHEDULE_TINY)
#define MIRA_SCHEDULE &schedule_tiny
#elif defined(USE_MIRA_SCHEDULE_MINUSCULE)
#define MIRA_SCHEDULE &schedule_minuscule
#else
#define MIRA_SCHEDULE &schedule_huge
#endif

typedef struct {
    uint8_t length;                    ///< Length of the radio packet
    uint8_t buffer[BUFFER_MAX_BYTES];  ///< Buffer containing the radio packet
} gateway_packet_t;

typedef struct {
    gateway_packet_t             radio_packet;                          ///< Queue used to process received radio packets outside of interrupt
    bool                         radio_packet_received;
    gateway_packet_t             uart_packet;                           ///< Queue used to process received UART bytes outside of interrupt
    bool                         uart_packet_received;
    gateway_packet_t             node_state_change_packet;              ///< Used to signal when a node joined or left
    bool                         node_state_change_packet_pending;
    uint32_t                     buttons;                               ///< Buttons state (one byte per button)
    bool                         led1_mira;                             ///< Whether the status LED should mira
    bool                         client_connected;
} gateway_vars_t;

//=========================== variables ========================================

extern schedule_t schedule_minuscule, schedule_tiny, schedule_huge;
static gateway_vars_t _gw_vars = { 0 };

//=========================== callbacks ========================================

static void _uart_callback(const uint8_t *data, size_t length) {
    memcpy(_gw_vars.uart_packet.buffer, data, length);
    _gw_vars.uart_packet.length   = length;
    _gw_vars.uart_packet_received = true;
}

void mira_event_callback(mr_event_t event, mr_event_data_t event_data) {
    switch (event) {
        case MIRA_NEW_PACKET:
        {
            _gw_vars.radio_packet.buffer[0] = MIRA_EDGE_DATA;
            memcpy(_gw_vars.radio_packet.buffer + 1, event_data.data.new_packet.header, sizeof(mr_packet_header_t));
            memcpy(_gw_vars.radio_packet.buffer + 1 + sizeof(mr_packet_header_t), event_data.data.new_packet.payload, event_data.data.new_packet.payload_len);
            _gw_vars.radio_packet.length   = sizeof(mr_packet_header_t) + event_data.data.new_packet.payload_len;
            _gw_vars.radio_packet_received = true;
            break;
        }
        case MIRA_KEEPALIVE:
        {
            _gw_vars.node_state_change_packet.buffer[0] = MIRA_EDGE_KEEPALIVE;
            memcpy(_gw_vars.node_state_change_packet.buffer + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
            _gw_vars.node_state_change_packet.length    = 1 + sizeof(uint64_t);
            _gw_vars.node_state_change_packet_pending   = true;
            break;
        }
        case MIRA_NODE_JOINED:
            puts("#");
            _gw_vars.node_state_change_packet.buffer[0] = MIRA_EDGE_NODE_JOINED;
            memcpy(_gw_vars.node_state_change_packet.buffer + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
            _gw_vars.node_state_change_packet.length = 1 + sizeof(uint64_t);
            _gw_vars.node_state_change_packet_pending = true;
            break;
        case MIRA_NODE_LEFT:
            puts("0");
            _gw_vars.node_state_change_packet.buffer[0] = MIRA_EDGE_NODE_LEFT;
            memcpy(_gw_vars.node_state_change_packet.buffer + 1, &event_data.data.node_info.node_id, sizeof(uint64_t));
            _gw_vars.node_state_change_packet.length = 1 + sizeof(uint64_t);
            _gw_vars.node_state_change_packet_pending = true;
            break;
        case MIRA_ERROR:
            puts("Error");
            break;
        default:
            break;
    }
}

static void _led1_mira_fast(void) {
    if (_gw_vars.led1_mira) {
        db_gpio_toggle(&db_led1);
    }
}

static void _led2_shutdown(void) {
    db_gpio_set(&db_led2);
}

static void _led3_shutdown(void) {
    db_gpio_set(&db_led3);
}

//=========================== main =============================================

int main(void) {
    db_hfclk_init();
    _gw_vars.led1_mira = true;
    // Initialize user feedback LEDs
    db_gpio_init(&db_led1, DB_GPIO_OUT);  // Global status
    db_gpio_set(&db_led1);
    db_timer_init(TIMER_DEV);
    db_timer_set_periodic_ms(TIMER_DEV, 0, 50, _led1_mira_fast);
    db_timer_set_periodic_ms(TIMER_DEV, 1, 20, _led2_shutdown);
    db_timer_set_periodic_ms(TIMER_DEV, 2, 20, _led3_shutdown);
    db_gpio_init(&db_led2, DB_GPIO_OUT);  // Packet received from Radio (e.g from a DotBot)
    db_gpio_set(&db_led2);
    db_gpio_init(&db_led3, DB_GPIO_OUT);  // Packet received from UART (e.g from the computer)
    db_gpio_set(&db_led3);

    // Configure Radio as transmitter
    mira_init(MIRA_GATEWAY, SWARMIT_MIRA_NET_ID, MIRA_SCHEDULE, &mira_event_callback);

    // Initialize the gateway context
    _gw_vars.buttons             = 0x0000;
    swarmit_uart_init(UART_INDEX, &db_uart_rx, &db_uart_tx, UART_BAUDRATE, &_uart_callback);

    // Initialization done, wait a bit and shutdown status LED
    db_timer_delay_s(TIMER_DEV, 1);
    db_gpio_set(&db_led1);
    _gw_vars.led1_mira = false;

    puts("Gateway is ready");

    while (1) {

        if (_gw_vars.node_state_change_packet_pending) {
            if (_gw_vars.client_connected) {
                swarmit_uart_write(UART_INDEX, _gw_vars.node_state_change_packet.buffer, _gw_vars.node_state_change_packet.length);
            }
            _gw_vars.node_state_change_packet_pending = false;
        }

        if (_gw_vars.radio_packet_received) {
            db_gpio_clear(&db_led2);
            if (_gw_vars.client_connected) {
                swarmit_uart_write(UART_INDEX, _gw_vars.radio_packet.buffer, _gw_vars.radio_packet.length);
            }
            _gw_vars.radio_packet_received = false;
        }

        if (_gw_vars.uart_packet_received) {
            db_gpio_clear(&db_led3);
            if (!_gw_vars.client_connected && _gw_vars.uart_packet.buffer[0] == 0xff) {
                _gw_vars.client_connected = true;
                puts("UART client connected");

                gateway_packet_t packet = { 0 };
                packet.buffer[0] = MIRA_EDGE_GATEWAY_INFO;
                size_t len = mr_build_uart_packet_gateway_info(packet.buffer + 1);
                packet.length = 1 + len;
                swarmit_uart_write(UART_INDEX, packet.buffer, packet.length);
            } else if (_gw_vars.uart_packet.buffer[0] == 0xfe) {
                _gw_vars.client_connected = false;
                puts("UART client disconnected");
            } else {
                mr_packet_header_t *header = (mr_packet_header_t *)_gw_vars.uart_packet.buffer;
                header->src = db_device_id();
                header->version = MIRA_PROTOCOL_VERSION;
                header->type = MIRA_PACKET_DATA;
                memcpy(_gw_vars.uart_packet.buffer, header, sizeof(mr_packet_header_t));
                mira_tx(_gw_vars.uart_packet.buffer, _gw_vars.uart_packet.length);
            }
            _gw_vars.uart_packet_received = false;
        }

    }
}
