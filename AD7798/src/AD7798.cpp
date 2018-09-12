#include "AD7798.h"

#include <cassert>
#include <functional>
#include <iostream>

/* Commands */
#define COM_READ_ID                 (0x60)  /* 01100000 */
#define COM_READ_MODE               (0x48)  /* 01001000 */
#define COM_WRITE_MODE              (0x8)   /* 00001000 */
#define COM_READ_STATUS             (0x40)  /* 01000000 */
#define COM_READ_DATA               (0x58)  /* 01011000 */
#define COM_READ_CONTINUOUS         (0x5C)  /* 01011100 */

/* Registers */
#define REG_COMM		0 /* Communications Register(WO, 8-bit) */
#define REG_STAT	    0 /* Status Register	    (RO, 8-bit) */
#define REG_MODE	    1 /* Mode Register	     	(RW, 16-bit */
#define REG_CONF	    2 /* Configuration Register (RW, 16-bit)*/
#define REG_DATA	    3 /* Data Register	     	(RO, 16-/24-bit) */
#define REG_ID	        4 /* ID Register	     	(RO, 8-bit) */
#define REG_IO	        5 /* IO Register	     	(RO, 8-bit) */
#define REG_OFFSET      6 /* Offset Register	    (RW, 24-bit */
#define REG_FULLSALE    7 /* Full-Scale Register	(RW, 24-bit */
#define STAT_RDY		    (1 << 7) /* Ready */

/* Reset Registers values */
#define RESET_REG_ID     (0x8);      /* 00001000 */
#define RESET_REG_STAT   (0x80);     /* 10000000 */
#define RESET_REG_MODE   (0x000A);   /* 0000000000001010 */
#define RESET_REG_CONF   (0x0710);   /* 0000011100010000 */
#define RESET_REG_DATA   (0x0000);   /* 0000000000000000 */
#define RESET_REG_IO     (0x00);     /* 00000000 */
#define RESET_REG_OFFSET (0x8000);   /* 1000000000000000 */

/* Mode select */
#define MODE_SELECT_SHIFT           (13)    /* bits[15:13] */
#define CONTINUOUS_CONVERSION_MODE  (0x0)
#define SINGLE_CONVERSION_MODE      (0x1)
#define IDLE_MODE                   (0x2)

#define MAX_FREQUENCY       (5000000)

/* Rate */
#define fADC_RESET              (16.7)                                            /* hertz */
#define CONVERSION_TIME         ((uint64_t) ((double)1/fADC_RESET * 1000000000))  /* ns */
#define FIRST_CONVERSION_TIME   ((uint64_t) (2 * CONVERSION_TIME))                /* ns */


/* Print debug logs */
//#define PRINT_DEBUG
#ifdef PRINT_DEBUG
#define DEBUG(x) std::cout << "AD7798: " + std::string(x) + "\n";
#else
#define DEBUG(x)
#endif
/* * * * * * * * * */

AD7798::AD7798() {
    int cs_pin_number = GetPinNumber("cs");
    int sck_pin_number = GetPinNumber("sck");
    int si_pin_number = GetPinNumber("si");
    int so_pin_number = GetPinNumber("so");

    SpiSlaveConfig spi_config;
    
    spi_config.mosi_pin_number = si_pin_number;
    spi_config.miso_pin_number = so_pin_number;
    spi_config.ss_pin_number = cs_pin_number;
    spi_config.sclk_pin_number = sck_pin_number;
    spi_config.supported_spi_modes = SPI_MODE_0 | SPI_MODE_1 | SPI_MODE_2 | SPI_MODE_3; //todo: check which modes are supported
    spi_config.max_frequency = MAX_FREQUENCY;
    spi_config.bit_order = MSB_FIRST;
    

    spi_slave_ = CreateSpiSlave(spi_config);

    Reset();
}

void AD7798::Main() {
    DEBUG(__FUNCTION__);

    while (!should_stop_) {
        MainSwitch();
    }
}

void AD7798::MainSwitch() {
    uint8_t comm_reg = 0;

    const auto byte_received = spi_slave_->Transmit(&comm_reg, nullptr, 1);
    if (byte_received == 0) return; /* loop until master write */

    DEBUG("comm_reg: " + std::to_string(comm_reg));

    /* A reset occurs if 32 consecutive 1s are seen on DIN */
    four_previous_bytes_ = (four_previous_bytes_ << 8) | comm_reg;
    if (four_previous_bytes_ == 0xFFFFFFFF) Reset();
    /* * */

    switch (comm_reg) {
        case COM_READ_ID: {
            ComReadId();
            break;
        }

        case COM_READ_MODE: {
            ComReadMode();
            break;
        }

        case COM_WRITE_MODE: {
            ComWriteMode();
            break;
        }

        case COM_READ_STATUS: {
            ComReadStatus();
            break;
        }

        case COM_READ_DATA: {
            ComReadData();
            break;
        }

        case COM_READ_CONTINUOUS: {
            ComReadContinuous();
            break;
        }

        case 0xFF: {
            // do noting
            break;
        }

        default: {
            throw std::logic_error("AD7798: Unsupported command " + std::to_string(comm_reg));
        }
    }
}

uint8_t AD7798::ModeSelect(uint16_t mode_reg) {
    return (uint8_t)(mode_reg >> MODE_SELECT_SHIFT);
}

void AD7798::Reset() {
    DEBUG(__FUNCTION__);

    regs_[REG_ID]       = RESET_REG_ID;
    regs_[REG_STAT]     = RESET_REG_STAT;
    regs_[REG_MODE]     = RESET_REG_MODE;
    regs_[REG_CONF]     = RESET_REG_CONF;
    regs_[REG_DATA]     = RESET_REG_DATA;
    regs_[REG_IO]       = RESET_REG_IO;
    regs_[REG_OFFSET]   = RESET_REG_OFFSET;

    if (continuous_conversion_timer_id_ != -1) {
        CancelTimedCallback(continuous_conversion_timer_id_);
        continuous_conversion_timer_id_ = -1;
    }
    four_previous_bytes_ = 0x0;
}

void AD7798::StartConversion(uint8_t conversion_mode) {
    DEBUG(__FUNCTION__);
    switch (conversion_mode) {
        case CONTINUOUS_CONVERSION_MODE: {
            ContinuousConversion();
            break;
        }
        case SINGLE_CONVERSION_MODE: {
            SingleConversion();
            break;
        }
        case IDLE_MODE: {
            DEBUG("IDLE_MODE");
            Reset();
            break;
        }
        default: {
            throw std::logic_error("AD7798: Unsupported conversion mode " + std::to_string(conversion_mode));
        }
    }
}

/*
 * Single-Conversion Mode.
 * When single-conversion mode is selected, the ADC powers up and performs a single conversion.
 * The conversion result is placed in the data register, RDY goes low, and the ADC returns to power-down mode.
 * The conversion remains in the data register and RDY remains active (low) until the data is read or another conversion is performed.
 * */
void AD7798::SingleConversion() {
    DEBUG(__FUNCTION__);
    if (continuous_conversion_timer_id_ != -1) {
        CancelTimedCallback(continuous_conversion_timer_id_);
        continuous_conversion_timer_id_ = -1;
    }

    SetReady(HIGH);
    DoConversion();
}

/*
 * Continuous-Conversion Mode (Default).
 * In continuous-conversion mode, the ADC continuously performs conversions and places the result in the data register.
 * Subsequent conversions are available at a frequency of fADC.
 * RDY goes low when a conversion is complete.
 * */
void AD7798::ContinuousConversion() {
    /* First conversions */
    SetReady(HIGH);
    DoConversion();

    /* Subsequent conversions */
    callback_t callback = std::bind(&AD7798::DoConversion, this);
    const auto time_until_callback = CONVERSION_TIME;
    continuous_conversion_timer_id_ = AddTimedCallback(time_until_callback, callback, false);
}

void AD7798::DoConversion() {
    DEBUG(__FUNCTION__);
    const uint16_t value = GetNextConversionValue();
    regs_[REG_DATA] = value;    /* The conversion result is placed in the data register */
    DEBUG("Writes to: regs_[REG_DATA] - " + std::to_string(regs_[REG_DATA]));
    SetReady(LOW);              /* RDY goes low */
}

uint16_t AD7798::GetNextConversionValue() {
    auto value =  GetNextInt16FromDataGenerator("conversion");
    return (uint16_t) value;
}

void AD7798::SetReady(Ready value) {
    const auto status = regs_[REG_STAT];
    regs_[REG_STAT] = (value == LOW) ? status & ~STAT_RDY : status | STAT_RDY;

    const auto rdy_dout_pin = GetPinNumber("so");
    SetPinLevel(rdy_dout_pin, value);
}

uint8_t AD7798::GetReady() {
    return (uint8_t) regs_[REG_STAT] >> 7;
}

void AD7798::ComReadId() {
    DEBUG(__FUNCTION__);
    auto data = (uint8_t) regs_[REG_ID];
    spi_slave_->Transmit(nullptr, &data, 1);
}

void AD7798::ComReadMode() {
    DEBUG(__FUNCTION__);
    uint8_t data[2] {(uint8_t)(regs_[REG_MODE] >> 8), (uint8_t)(regs_[REG_MODE] & 0xFF)};
    spi_slave_->Transmit(nullptr, data, 2);
    DEBUG("Reads from: regs_[REG_MODE] - " + std::to_string(regs_[REG_MODE]));
}

uint16_t AD7798::ReadShort() {
    uint8_t data[2] {};
    if (spi_slave_->Transmit(data, nullptr, 2) != 2 || !spi_slave_->IsSsActive()) {
        throw std::logic_error("AD7798: error");
    }
    return (data[0] << 8) | (data[1] << 0);
}

void AD7798::WriteShort(uint16_t short_num) {
    uint8_t data[2] {(uint8_t)(short_num >> 8), (uint8_t)(short_num & 0xFF)};
    spi_slave_->Transmit(nullptr, data, 2);
}

void AD7798::ComWriteMode() {
    DEBUG(__FUNCTION__);

    const uint16_t mode_reg = ReadShort();

    const auto conversion_mode = ModeSelect(mode_reg);

    /* The oscillator requires 1 ms to power up and settle.
     * First conversion is available after a period of 2/fADC */
    callback_t callback = std::bind(&AD7798::StartConversion, this, conversion_mode);
    const auto time_until_callback = 1000000 + FIRST_CONVERSION_TIME;
    AddTimedCallback(time_until_callback, callback, true);
}

void AD7798::ComReadStatus() {
    //DEBUG(__FUNCTION__);
    auto data = (uint8_t) regs_[REG_STAT];
    spi_slave_->Transmit(nullptr, &data, 1);
    //DEBUG("regs_[REG_STAT] - " + std::to_string(data));
}

void AD7798::ComReadData() {
    DEBUG(__FUNCTION__);
    ReadData();
}

void AD7798::ReadData() {
    if (GetReady() == HIGH) return;
    WriteShort((uint16_t) regs_[REG_DATA]);
    DEBUG("Reads from: regs_[REG_DATA] - " + std::to_string(regs_[REG_DATA]));
    SetReady(HIGH);
}

void AD7798::ComReadContinuous() {
    DEBUG(__FUNCTION__);
    SetReady(HIGH);
    HandleContinuousReadMode();
}

void AD7798::HandleContinuousReadMode() {
    DEBUG(__FUNCTION__);
    while (true) {
        uint8_t rx_buffer[2] {};
        uint8_t tx_buffer[2] { (uint8_t)(regs_[REG_DATA] >> 8), (uint8_t)(regs_[REG_DATA] & 0xFF) };

        const auto len = spi_slave_->Transmit(rx_buffer, tx_buffer, 2);
        if (len == 0) continue;
        DEBUG("Reads from: regs_[REG_DATA] - " + std::to_string(regs_[REG_DATA]));

        SetReady(HIGH);

        const uint8_t first_byte  = rx_buffer[0];
        const uint8_t second_byte = rx_buffer[1];

        /* Check if stop is called */
        if (first_byte == COM_READ_DATA || second_byte == COM_READ_DATA) {
            DEBUG("COM_READ_DATA - IN CONTINUOUS READ MODE");
            return;
        }

        /* A reset occurs if 32 consecutive 1s are seen on DIN */
        for (const auto receieved_byte : rx_buffer) {
            four_previous_bytes_ = (four_previous_bytes_ << 8) | receieved_byte;
            if (four_previous_bytes_ == 0xFFFFFFFF) {
                Reset();
                return;
            }
        }
        /* * */
    }
}




