#pragma once

#include <cstdio>
#include <cstdint>


struct UartFlowControlConfig {
    uint32_t cts_pin{};
    uint32_t rts_pin{};
    bool cts_enable_{false};
    bool rts_enable_{false};
};

struct UartConfig {
    uint32_t baud_rate{};
    uint32_t stop_bits{};
    bool parity{};
    uint32_t rx_pin{};
    uint32_t tx_pin{};
    UartFlowControlConfig flow_control{};
};



class iUartDeviceV1 {

    public:
        // Returns immediately
        virtual  size_t Write(const char* data, size_t len) = 0;

        // Returns when all bytes were received
        virtual size_t Read(char* data, size_t len) = 0;

        virtual void CancelRead() = 0;
};

typedef iUartDeviceV1 iUartDevice;
