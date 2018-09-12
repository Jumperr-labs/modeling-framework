#pragma once
#include "ModelingFramework.h"
#include "iI2cSlave.h"

class I2CDummySlave : public ExternalPeripheral {
  private:
    iI2cSlave* i2c_slave_ {};
    const uint8_t kDeviceAddress_  = 0x2D;
  public:
    I2CDummySlave();
    void Main() override {
        return;
    };
    void Stop() override {
        return;
    };

    I2CDummySlave(const I2CDummySlave&) = delete;
    I2CDummySlave& operator=(const I2CDummySlave&) = delete;

    void OnMasterRead(uint8_t device_address, iI2cSlaveBaseWriteStream& i2c_slave_read_stream);
    void OnMasterWrite(uint8_t device_address, iI2cSlaveBaseReadStream& i2c_slave_write_stream);
};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new I2CDummySlave();
}