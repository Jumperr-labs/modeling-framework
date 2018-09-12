#pragma once
#include "ModelingFramework.h"

class AD7798 : public ExternalPeripheral {
  public:
    AD7798();
    void Main() override;
    void Stop() override {
        should_stop_ = true;
    };

  private:

    enum Ready {LOW=0, HIGH=1};

    /* Members */
    bool should_stop_ {false};
    iSpiSlaveV1* spi_slave_ {};
    uint32_t regs_[8];
    int continuous_conversion_timer_id_ {-1};
    uint32_t four_previous_bytes_ {};

    /* Commands */
    void ComReadId();
    void ComReadMode();
    void ComWriteMode();
    void ComReadStatus();
    void ComReadData();
    void ComReadContinuous();

    /* Other Methods */
    void Reset();
    void StartConversion(uint8_t conversion_mode);
    void ContinuousConversion();
    void SingleConversion();
    void DoConversion();
    uint16_t GetNextConversionValue();
    uint8_t ModeSelect(uint16_t mode_reg);
    void SetReady(Ready);
    uint8_t GetReady();
    uint16_t ReadShort();
    void WriteShort(uint16_t);
    void MainSwitch();
    void ReadData();
    void HandleContinuousReadMode();

    friend class Ad7798Test;
};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new AD7798();
}
