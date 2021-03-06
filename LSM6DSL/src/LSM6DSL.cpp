#include "LSM6DSL.h"

#include <functional>
#include <iostream>
#include <cassert>
#include <cstring>
#include <math.h>

#define OP_INT1_CTRL (0xD)
#define OP_INT2_CTRL (0xE)

// Interrupt registers
#define WAKE_UP_SRC (0x1B)
#define TAP_SRC (0x1C)
#define D6D_SRC (0x1D)
#define DRDY_PULSE_CFG_G (0xB)

#define CTRL3_C (0x12)
#define BDU_BIT (0x1 << 6)
#define IF_INC (0x1 << 2)

#define STATUS_REG (0x1E)
#define SENSORHUB1_REG (0x2E)

#define FIFO_CTRL1 (0x6)
#define FIFO_CTRL2 (0x7)
#define FIFO_CTRL3 (0x8)
#define FIFO_CTRL4 (0x9)
#define FIFO_CTRL5 (0xA)

#define FIFO_STATUS1 (0x3a) // Number of unread words (16-bit axes) stored in FIFO
#define FIFO_STATUS2 (0x3b) // FIFO status control register
#define FIFO_STATUS3 (0x3c) // Word of recursive pattern read at the next reading
#define FIFO_STATUS4 (0x3d) // Word of recursive pattern read at the next reading

#define FIFO_DATA_OUT_L (0x3E) // FIFO data output (first byte)
#define FIFO_DATA_OUT_H (0x3F) // FIFO data output (second byte)

// FIFO_STATUS2

// Number of unread words
#define DIFF_FIFO (0xB)

//0: FIFO contains data
// 1: FIFO is empty
#define FIFO_EMPTY (0x1 << 4)

// 0: FIFO is not full
// 1: FIFO will be full at the next ODR
#define FIFO_FULL_SMART (0x1 << 5)

// 0: FIFO is not completely filled
// 1: FIFO is completely filled
#define OVER_RUN (0x1 << 6)

// 0: FIFO filling is lower than watermark level,
// 1: FIFO filling is equal to or higher than the watermark level
#define WATER_M (0x1 << 7)

#define REG_ADDRESS_MASK (0xFE)
#define MODE_MASK (0x7)
#define FIFO_ODR_MASK (0x78)

#define WRITE_TO_REG (0x0)
#define READ_TO_REG (0x1)
#define READ_WRITE_BIT_MASK (0x1)

#define REG_ADDRESS_MASK (0xFE)

#define DEVICE_CODE (0x11010110)

#define MAX_FREQUENCY (10000000)

#define DATA_READY_PULSES_MICROSECOND (75)

LSM6DSL::LSM6DSL() :
        mode_(FIFO_MODE_BYPASS),
        fifo_odr_(0),
        fifo_(),
        out_l_was_read(false),
        out_h_was_read(false),
        should_stop_(false),
        timer_id_(0),
        odr_(),
        output_regs_update_(false){
    int cs_pin_number = GetPinNumber("cs");
    int sck_pin_number = GetPinNumber("sck");
    int si_pin_number = GetPinNumber("si");
    int so_pin_number = GetPinNumber("so");
    sa0_pin_number_ = GetPinNumber("sa0");
    int1_pin_number_ = GetPinNumber("int1");
    int2_pin_number_ = GetPinNumber("int2");
    SpiSlaveConfig spi_config;
    spi_config.mosi_pin_number = si_pin_number;
    spi_config.miso_pin_number = so_pin_number;
    spi_config.ss_pin_number = cs_pin_number;
    spi_config.sclk_pin_number = sck_pin_number;
    spi_config.supported_spi_modes = SPI_MODE_0 | SPI_MODE_3;
    spi_config.max_frequency = MAX_FREQUENCY;
    spi_config.bit_order = MSB_FIRST;

    spi_slave_ = CreateSpiSlave(spi_config);
    MemReset();
    odr_ = {{0,0}, {1,12.5}, {2,26}, {3,52}, {4,104}, {5,208}, {6,416}, {7,833}, {8,1660}, {9,3330}, {10,6660}};
}

void LSM6DSL::Main() {
    while (!should_stop_) {
        uint8_t opcode = 0;
        if (spi_slave_->Transmit(&opcode, nullptr,  1) == 0) {
            continue;
        }
        uint32_t reg_address = (opcode & REG_ADDRESS_MASK) >> 0x1;
        if ((opcode & READ_WRITE_BIT_MASK) == WRITE_TO_REG) {
            ReadDataFromMaster(reg_address);
        } else {
            WriteDataToMaster(reg_address);
        }
    }
}

void LSM6DSL::WriteToFifoCntrl5(uint8_t value) {
    fifo_odr_ = odr_[((value & FIFO_ODR_MASK) >> 3)];
    UpdateOdr();

    uint8_t current_mode = mode_;
    mode_ = (fifo_mode_t)(value & MODE_MASK);
    if ((mode_ != FIFO_MODE_BYPASS) && (mode_ != FIFO_MODE_FIFO)) {
        throw std::logic_error("LSM6DSL: Unsupported mode " + std::to_string(mode_));
    }

    if (mode_ == FIFO_MODE_BYPASS) {
        ClearFifo();
    } else if (mode_ == FIFO_MODE_FIFO && current_mode != FIFO_MODE_FIFO) {
        LoadDataIntoOutputRegs();
    }
    memory_[FIFO_CTRL5] = value;
}

// Loads data from data-generator to fifo (rate: ODR_FIFO_ defined in WriteToFifoCntrl5)
void LSM6DSL::UpdateOdr() {
    if (fifo_odr_ == 0){
        if (timer_id_ != 0) {
            CancelTimedCallback(timer_id_);
            timer_id_ = 0;
        }
    } else if (timer_id_ != 0) {
        UpdateTimedCallback(timer_id_, ((pow(10, 9))/fifo_odr_));
    } else {
        timer_id_ = AddTimedCallback((pow(10, 9))/(fifo_odr_), std::bind(&LSM6DSL::TimerCallback, this), false);
    }
}

void LSM6DSL::WriteToDrdyPulseCfg(uint8_t value) {
    if ((value & (0x1 << 7)) > 0) {
        // Set data load mode
    }
    memory_[D6D_SRC] = value;
}

void LSM6DSL::TimerCallback() {
    if(fifo_.size() < MAX_FIFO_SIZE){
        uint16_t sample =  GetNextInt16FromDataGenerator("accelerometer");
        fifo_.push(sample);
        if (!output_regs_update_) {
            LoadDataIntoOutputRegs();
        }
    }
}

void LSM6DSL::LoadDataIntoOutputRegs() {
    if (fifo_.empty()) {
        output_regs_update_ = false;
        return;
    }
    uint16_t value = fifo_.front();
    fifo_.pop();
    memory_[FIFO_DATA_OUT_L] = (uint8_t)(value & 0xFF);
    out_l_was_read = false;
    memory_[FIFO_DATA_OUT_H] = (uint8_t)((value & 0xFF00) >> 8);
    out_h_was_read = false;
    output_regs_update_ = true;
}

void LSM6DSL::ClearFifo() {
    std::queue<uint16_t> empty;
    std::swap(fifo_, empty);
    out_l_was_read = false;
    out_h_was_read = false;
}

void LSM6DSL::WriteDataToMaster(uint32_t start_reg_address) {
    uint32_t current_reg_address = start_reg_address;

    // Reading
    while (spi_slave_->IsSsActive()) {
        uint8_t sample = memory_[current_reg_address];
        if (spi_slave_->Transmit(nullptr, &sample, 1) == 0) {
            continue;
        }

        if(current_reg_address == FIFO_DATA_OUT_L) {
            out_l_was_read = true;
        } else if (current_reg_address == FIFO_DATA_OUT_H) {
            out_h_was_read = true;
        }

        if (IsBduBitSet() && out_h_was_read && out_l_was_read) {
            LoadDataIntoOutputRegs();
        }

        if (!IsBduBitSet() && (out_h_was_read || out_l_was_read)) {
            // Implement each data should be loaded into regs and under which conditions
            LoadDataIntoOutputRegs();
        }

        if (IsIfIncSet()) {
            current_reg_address = (current_reg_address + 1) % MEMORY_SIZE;
        }
    }
}

void LSM6DSL::ReadDataFromMaster(uint32_t start_reg_address) {
    uint32_t current_reg_address = start_reg_address;
    uint8_t data;
    // Reading
    while (spi_slave_->IsSsActive()) {
        if (spi_slave_->Transmit(&data, nullptr, 1) == 0) {
            continue;
        }
        switch (current_reg_address) {
            case (FIFO_CTRL5): {
                WriteToFifoCntrl5(data);
                break;
            }

            case (DRDY_PULSE_CFG_G): {
                WriteToDrdyPulseCfg(data);
                break;
            }

            default: {
               memory_[current_reg_address] = data;
            }
        }

        if (IsIfIncSet()) {
            // Implement handle write only regs
            current_reg_address = (current_reg_address + 1) % MEMORY_SIZE;
        }
    }
}

bool LSM6DSL::IsBduBitSet() {
    return (memory_[CTRL3_C] & BDU_BIT) > 0;
}

bool LSM6DSL::IsIfIncSet() {
    return (memory_[CTRL3_C] & IF_INC) > 0;
}

void LSM6DSL::Stop() {
    should_stop_ = true;
}

void LSM6DSL::MemReset() {
    memset(memory_, 0xff, MEMORY_SIZE);
}
