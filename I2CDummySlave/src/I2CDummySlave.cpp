#include "I2CDummySlave.h"
#include <functional>
#include <iostream>
#include <cassert>
#include <cstring>

I2CDummySlave::I2CDummySlave() {
    i2c_slave_ = CreateI2cSlave();
    i2c_slave_->SetMasterReadCommandCallback(std::bind(&I2CDummySlave::OnMasterRead,this,std::placeholders::_1, std::placeholders::_2));
    i2c_slave_->SetMasterWriteCommandCallback(std::bind(&I2CDummySlave::OnMasterWrite,this,std::placeholders::_1, std::placeholders::_2));
    i2c_slave_->SetSlaveAddress(kDeviceAddress_, 0x7F);
}

// On master read slave will send next number on the counter
void I2CDummySlave::OnMasterRead(uint8_t device_address, iI2cSlaveBaseWriteStream& i2c_slave_write_stream) {
    uint8_t slave_data_to_send = (uint8_t)0xA5;
    while (!i2c_slave_write_stream.ReceivedNack()) {
        i2c_slave_write_stream.Write(&slave_data_to_send, 1);
    }
}

void I2CDummySlave::OnMasterWrite(uint8_t device_address, iI2cSlaveBaseReadStream& i2c_slave_read_stream) {
    std::vector<uint8_t> buff;
    size_t number_of_byte_recevied_from_master;
    uint8_t value;
    // Read data from master
    while (!i2c_slave_read_stream.ReceivedStop()) {
        number_of_byte_recevied_from_master = i2c_slave_read_stream.ReadAndSendAck(&value, 1);
        if (number_of_byte_recevied_from_master < 1) {
            std::string str(buff.begin(), buff.end());
            std::cout << "data received: " << str << std::endl;
            return;
        }
        buff.push_back(value);
    }
}