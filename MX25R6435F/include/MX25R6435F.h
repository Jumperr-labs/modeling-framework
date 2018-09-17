#pragma once
#include "ModelingFramework.h"

#define MAX_FREQUENCY       (70000000)

class MX25R6435F : public ExternalPeripheral {
  public:
    MX25R6435F();
    void Main() override;
    void Stop() override {
        should_stop_ = true;
    };

  private:
    static const uint8_t kManufacturerId = 0xc2;
    static const uint8_t kMemoryType = 0x28;
    static const uint8_t kMemoryDensity = 0x17;

    // Rdid
    static const uint8_t kCommandRdid = 0x9f;
    static const size_t kRdidResponseSize = 3;

    // Rems
    static const uint8_t kCommandRems = 0x90;
    static const size_t kRemsResponseSize = 2;

    // Res
    static const uint8_t kCommandRes = 0xab;
    static const size_t kResResponseSize = 1;

    iSpiSlaveV1* spi_slave_ {};
    bool should_stop_ {false};
    uint8_t in_buffer_[256] {0};
    uint8_t kRdidResponse [3] {kManufacturerId, kMemoryType, kMemoryDensity};
    uint8_t kRemsResponse0[2] {kManufacturerId, kMemoryDensity};
    uint8_t kRemsResponse1[2] {kMemoryDensity, kManufacturerId};
    uint8_t kResResponse[1] {kMemoryDensity};



    void MainSwitch();

    /* Commands */
    void CommandRdid();
    void CommandRems();
    void CommandRes();

};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new MX25R6435F();
}
