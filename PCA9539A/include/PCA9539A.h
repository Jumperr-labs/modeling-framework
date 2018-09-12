#pragma once
#include "ModelingFramework.h"
#include "iI2cSlave.h"
#include <map>

#define MEMORY_SIZE (0x100000)

class PCA9539A : public ExternalPeripheral {
 public:
    PCA9539A();
    void Main() override {
        return;
    };
    void Stop() override {
        return;
    };

    PCA9539A(const PCA9539A&) = delete;
    PCA9539A& operator=(const PCA9539A&) = delete;

  private:
    typedef enum{
        P0 = 0,
        P1 = 1
    } port_num_t;

    static const uint32_t kNumberOfPinsInPort_ = 8;
    uint32_t p_[2][kNumberOfPinsInPort_];
    uint32_t a0_ {};
    uint32_t a1_ {};
    uint32_t reset_ {};
    uint32_t int_ {};
    std::map<uint8_t ,uint8_t> regs_;
    std::map<uint32_t ,port_num_t> pins_to_port_number_;
    std::map<uint32_t ,uint32_t > pins_to_index_;
    std::map<uint32_t ,pin_direction_t> pins_direction_;
    uint8_t reg_address_ {};
    uint8_t device_address_ {};
    bool is_reset_mode_ = false;
    uint8_t save_p0_input_reg_state_ {};
    uint8_t save_p1_input_reg_state_ {};
    port_num_t port_made_int_;

    iI2cSlave* i2c_slave_ {};
    void OnMasterRead(uint8_t device_address, iI2cSlaveBaseWriteStream& i2c_slave_read_stream);
    void OnMasterWrite(uint8_t device_address, iI2cSlaveBaseReadStream& i2c_slave_write_stream);
    void OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications);
    void WriteConfigurationValue(port_num_t port_num, uint8_t value, uint8_t current_configuration);
    void SetOutputPinValue(port_num_t port_num, uint8_t value, uint8_t current_value);
    void SetDeviceAddress();
    void UpdateInputPinLevel(port_num_t port_num, uint32_t pin_index, bool new_pin_level);
    void InitializePins();
    void Reset();
    void SetPinsChangeLevelCallbacks();
    bool IsInputRegEqualInputPins();
    uint8_t GetRegValue(uint8_t reg_address);
    ack SetRegValue(uint8_t reg_address, uint8_t value);

    const uint8_t kRegsSize_  = 0x8;
    // const
    const uint8_t kP0Input_  = 0x00;
    const uint8_t kP1Input_  = 0x01;
    const uint8_t kP0Output_ = 0x02;
    const uint8_t kP1Output_ = 0x03;
    const uint8_t kP0Inv_    = 0x04;
    const uint8_t kP1Inv_    = 0x05;
    const uint8_t kP0Conf_   = 0x06;
    const uint8_t kP1Conf_   = 0x07;
};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new PCA9539A();
}
