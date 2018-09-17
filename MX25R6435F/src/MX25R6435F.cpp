#include "MX25R6435F.h"

MX25R6435F::MX25R6435F() {
     int cs_pin_number = GetPinNumber("cs");
    int sck_pin_number = GetPinNumber("sck");
    int si_pin_number = GetPinNumber("si");
    int so_pin_number = GetPinNumber("so");

    SpiSlaveConfig spi_config;

    spi_config.mosi_pin_number = si_pin_number;
    spi_config.miso_pin_number = so_pin_number;
    spi_config.ss_pin_number = cs_pin_number;
    spi_config.sclk_pin_number = sck_pin_number;
    spi_config.supported_spi_modes = SPI_MODE_0 | SPI_MODE_3; //todo: check which modes are supported
    spi_config.max_frequency = MAX_FREQUENCY;
    spi_config.bit_order = MSB_FIRST;

    spi_slave_ = CreateSpiSlave(spi_config);
}


void MX25R6435F::Main() {
    while (!should_stop_) {
        MainSwitch();
    }
}

void MX25R6435F::MainSwitch() {
    /* Read command - one byte */
    const auto byte_received = spi_slave_->Transmit(in_buffer_, nullptr, 1);
    if (byte_received == 0) return; /* loop until master write */
    switch (in_buffer_[0]) {
        case kCommandRdid: {
            CommandRdid();
            break;
        }
        case kCommandRems: {
            CommandRems();
            break;
        }
        case kCommandRes: {
            CommandRes();
            break;
        }
        default: {
            break;
        }
    }
}

/********************************
  commands
 ********************************/

void MX25R6435F::CommandRdid() {
    spi_slave_->Transmit(nullptr, kRdidResponse, kRdidResponseSize);
}

void MX25R6435F::CommandRems() {
    const auto dummy_bytes_received = spi_slave_->Transmit(in_buffer_, nullptr, 2); //2 dummy Bytes
    if (dummy_bytes_received == 0) return;

    const auto add_byte_received = spi_slave_->Transmit(in_buffer_, nullptr, 1);  //ADD Byte
    if (add_byte_received == 0) return;

    if ((in_buffer_[0] & 1) == 0) {
        spi_slave_->Transmit(nullptr, kRemsResponse0, kRemsResponseSize);
    } else {
        spi_slave_->Transmit(nullptr, kRemsResponse1, kRemsResponseSize);
    }
}

void MX25R6435F::CommandRes() {
    const auto byte_received = spi_slave_->Transmit(in_buffer_, nullptr, 3);
    if (byte_received == 0) return;

    spi_slave_->Transmit(nullptr, kResResponse, kResResponseSize);
}