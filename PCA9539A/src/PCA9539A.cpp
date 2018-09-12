#include "PCA9539A.h"
#include <functional>
#include <iostream>
#include <cassert>
#include <cstring>

PCA9539A::PCA9539A() :
      regs_(), pins_to_port_number_(),
      pins_to_index_(),
      pins_direction_(),
      port_made_int_(P0) {
        i2c_slave_ = CreateI2cSlave();
        i2c_slave_->SetMasterReadCommandCallback(std::bind(&PCA9539A::OnMasterRead,this,std::placeholders::_1, std::placeholders::_2));
        i2c_slave_->SetMasterWriteCommandCallback(std::bind(&PCA9539A::OnMasterWrite,this,std::placeholders::_1, std::placeholders::_2));
        InitializePins();
        SetDeviceAddress();
        is_reset_mode_ = GetPinLevel(reset_);
}

void PCA9539A::InitializePins() {
    p_[0][0] = GetPinNumber("P00");
    p_[0][1] = GetPinNumber("P01");
    p_[0][2] = GetPinNumber("P02");
    p_[0][3] = GetPinNumber("P03");
    p_[0][4] = GetPinNumber("P04");
    p_[0][5] = GetPinNumber("P05");
    p_[0][6] = GetPinNumber("P06");
    p_[0][7] = GetPinNumber("P07");
    p_[1][0] = GetPinNumber("P10");
    p_[1][1] = GetPinNumber("P11");
    p_[1][2] = GetPinNumber("P12");
    p_[1][3] = GetPinNumber("P13");
    p_[1][4] = GetPinNumber("P14");
    p_[1][5] = GetPinNumber("P15");
    p_[1][6] = GetPinNumber("P16");
    p_[1][7] = GetPinNumber("P17");

    a0_    = GetPinNumber("A0");
    a1_    = GetPinNumber("A1");
    int_   = GetPinNumber("INT");
    reset_ = GetPinNumber("RESET");

    pins_to_port_number_ = {{p_[0][0], P0}, {p_[0][1], P0}, {p_[0][2], P0}, {p_[0][3], P0},
                            {p_[0][4], P0}, {p_[0][5], P0}, {p_[0][6], P0}, {p_[0][7], P0},
                            {p_[1][0], P1}, {p_[1][1], P1}, {p_[1][2], P1}, {p_[1][3], P1},
                            {p_[1][4], P1}, {p_[1][5], P1}, {p_[1][6], P1}, {p_[1][7], P1}};

    pins_to_index_ = {{p_[0][0], 0}, {p_[0][1], 1}, {p_[0][2], 2}, {p_[0][3], 3},
                      {p_[0][4], 4}, {p_[0][5], 5}, {p_[0][6], 6}, {p_[0][7], 7},
                      {p_[1][0], 0}, {p_[1][1], 1}, {p_[1][2], 2}, {p_[1][3], 3},
                      {p_[1][4], 4}, {p_[1][5], 5}, {p_[1][6], 6}, {p_[1][7], 7}};

    SetPinsChangeLevelCallbacks();
}

void PCA9539A::Reset() {
    uint8_t reg_input_p0 = 0x00;
    uint8_t reg_input_p1 = 0x00;
    // Set all pin as input pins and set to value high
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0; j < kNumberOfPinsInPort_; j++) {
            if (GetPinLevel(p_[i][j])) {
                auto setToHigh = (uint8_t) (1U << j);
                if (i == P0) {
                    reg_input_p0 |= setToHigh;
                } else {
                    reg_input_p1 |= setToHigh;
                }
            }
        }
    }

    // reset interrupt pin
    SetPinLevel(int_, true);
    pins_direction_ = {{p_[0][0], DIRECTION_IN}, {p_[0][1], DIRECTION_IN}, {p_[0][2], DIRECTION_IN}, {p_[0][3], DIRECTION_IN},
                       {p_[0][4], DIRECTION_IN}, {p_[0][5], DIRECTION_IN}, {p_[0][6], DIRECTION_IN}, {p_[0][7], DIRECTION_IN},
                       {p_[1][0], DIRECTION_IN}, {p_[1][1], DIRECTION_IN}, {p_[1][2], DIRECTION_IN}, {p_[1][3], DIRECTION_IN},
                       {p_[1][4], DIRECTION_IN}, {p_[1][5], DIRECTION_IN}, {p_[1][6], DIRECTION_IN}, {p_[1][7], DIRECTION_IN}};

    regs_ = {{kP0Input_, reg_input_p0}, {kP1Input_, reg_input_p1}, {kP0Output_, 0xff}, {kP1Output_, 0xff},
             {kP0Inv_, 0x00}, {kP1Inv_, 0x00}, {kP0Conf_, 0xff}, {kP1Conf_, 0xff}};
}

void PCA9539A::SetPinsChangeLevelCallbacks() {
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0; j < kNumberOfPinsInPort_; j++) {
            SetPinChangeLevelEventCallback(p_[i][j], std::bind(&PCA9539A::OnPinChangeLevelEvent,this,std::placeholders::_1));
        }
    }
    SetPinChangeLevelEventCallback(a0_, std::bind(&PCA9539A::OnPinChangeLevelEvent,this,std::placeholders::_1));
    SetPinChangeLevelEventCallback(a1_, std::bind(&PCA9539A::OnPinChangeLevelEvent,this,std::placeholders::_1));
    SetPinChangeLevelEventCallback(reset_, std::bind(&PCA9539A::OnPinChangeLevelEvent,this,std::placeholders::_1));
}

void PCA9539A::SetDeviceAddress() {
    int is_a0_high = GetPinLevel(a0_);
    int is_a1_high = GetPinLevel(a1_);

    device_address_ = (uint8_t) (0x74 | (is_a1_high << 1) | is_a0_high);
    i2c_slave_->SetSlaveAddress(device_address_, 0x7F);
}

ack PCA9539A::SetRegValue(uint8_t reg_address, uint8_t value) {
    auto find_reg_data = regs_.find(reg_address_);
    if (find_reg_data == regs_.end()) {
        return false;
    }

    uint8_t current_value = find_reg_data->second;
    if (reg_address_ == kP0Input_ || reg_address_ == kP1Input_) {
        return false;
    }

    if (reg_address_ == kP0Output_) {
        SetOutputPinValue(P0, value, current_value);
    } else if (reg_address_ == kP1Output_) {
        SetOutputPinValue(P1, value, current_value);
    } else if (reg_address_ == kP0Conf_) {
        WriteConfigurationValue(P0, value, current_value);
    } else if (reg_address_ == kP1Conf_) {
        WriteConfigurationValue(P1, value, current_value);
    } else if (reg_address_ == kP0Input_ || reg_address_ == kP1Input_) {
        return false;
    } else if (reg_address_ != kP0Inv_ && reg_address_ != kP1Inv_) {
        return false;
    }

    regs_[reg_address_] = value;
    return true;
}


uint8_t  PCA9539A::GetRegValue(uint8_t reg_address) {
    auto find_reg_data = regs_.find(reg_address);
    uint8_t current_value = find_reg_data->second;
    if (reg_address_ == kP0Input_) {
        if (port_made_int_ == P0) {
            SetPinLevel(int_, true);
        }
        auto find_reg_inv_data = regs_.find(kP0Inv_);
        current_value ^= find_reg_inv_data->second;
    } else if (reg_address_ == kP1Input_) {
        if (port_made_int_ == P1) {
            SetPinLevel(int_, true);
        }
        auto find_reg_inv_data = regs_.find(kP1Inv_);
        current_value ^= find_reg_inv_data->second;
    }
    return current_value;
}

void PCA9539A::WriteConfigurationValue(port_num_t port_num, uint8_t value, uint8_t current_configuration) {
    for (uint32_t i = 0; i < kNumberOfPinsInPort_; i++) {
        uint32_t mask = 1U << i;
        if ((value & mask) != (current_configuration & mask)) {
            pin_direction_t direction = value & mask ? DIRECTION_IN : DIRECTION_OUT;
            uint32_t address;
            if (direction == DIRECTION_IN) {
                bool pin_level = GetPinLevel(p_[port_num][i]);
                UpdateInputPinLevel(port_num, i, pin_level);
                address = port_num ? kP1Input_ : kP0Input_;
            } else {
                address = port_num ? kP1Output_ : kP0Output_;
            }
            SetPinDirection(p_[port_num][i], direction, (mask & regs_[address]));
            pins_direction_[p_[port_num][i]] = direction;
        }
    }
}

void PCA9539A::UpdateInputPinLevel(port_num_t port_num, uint32_t pin_index, bool new_pin_level) {
    // set to high the input pin
    if (new_pin_level) {
        uint32_t set_to_high = 1U << pin_index;
        if (port_num == P0) {
            regs_[kP0Input_] |= set_to_high;
        } else {
            regs_[kP1Input_] |= set_to_high;
        }
    } else {// set to low the the input pin
        uint32_t setToHigh = 1U << pin_index;
        if (port_num == P0) {
            regs_[kP0Input_] &= ~setToHigh;
        } else {
            regs_[kP1Input_] &= ~setToHigh;
        }
    }
}

void PCA9539A::SetOutputPinValue(port_num_t port_num, uint8_t new_value, uint8_t current_value) {
    std::map<uint8_t, uint8_t>::iterator find_reg_output_data;
    if (port_num == P0) {
        find_reg_output_data = regs_.find(kP0Conf_);
    } else {
        find_reg_output_data = regs_.find(kP1Conf_);
    }
    uint8_t conf = find_reg_output_data->second;
    uint8_t inv_conf = ~conf;

    pin_level_changes_t pin_changes;
    for (uint32_t i = 0; i < kNumberOfPinsInPort_; i++) {
        uint32_t mask = 1U << i;
        //check if the pin is input
        if (!(inv_conf & mask)) {
            continue;
        }
        if ((new_value & mask) != (current_value & mask)) {
            pin_changes.push_back(WireChange(p_[port_num][i], (new_value & mask) != 0, p_[port_num][i]));
            UpdateInputPinLevel(port_num, i, (new_value & mask) != 0);
        }
    }
    if (!pin_changes.empty()) {
        SetMultiplePinsLevel(pin_changes);
    }
}

bool PCA9539A::IsInputRegEqualInputPins() {
    for (uint32_t i = 0; i < 2; i++) {
        for (uint32_t j = 0; j < kNumberOfPinsInPort_; j++) {
            uint32_t mask = 1U << j;
            if (i == 0) {
                if ((GetPinLevel(p_[int(i)][j]) ? mask : 0) != (save_p0_input_reg_state_ & mask)) {
                    return false;
                }
            } else {
                if ((GetPinLevel(p_[int(i)][j]) ? mask : 0) != (save_p1_input_reg_state_ & mask)) {
                    return false;
                }
            }
        }
    }
    return true;
}

void PCA9539A::OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications) {
    bool update_address = false;
    bool reset_values = false;
    bool check_raise_int = false;

    for (WireLogicLevelEvent notification : notifications) {
        bool is_input_pin = true;
        uint32_t wire_num = notification.wire_number;

        if (wire_num == a0_ || wire_num == a1_) {
            is_input_pin = false;
            update_address = true;
        } else if (wire_num == reset_) {
            is_input_pin = false;
            if (notification.type == FALLING) {
                reset_values = true;
                is_reset_mode_ = true;
            } else {
                is_reset_mode_ = false;
            }
        }

        // Reset will update the input pin values
        if (reset_values || !is_input_pin) {
            continue;
        }

        //Only input pin can change the value
        if (pins_direction_[wire_num] == DIRECTION_OUT) {
            continue;
        } else {
            port_num_t port_num = pins_to_port_number_[wire_num];
            if (GetPinLevel(int_)) {
                SetPinLevel(int_, false);
                save_p0_input_reg_state_ = regs_[kP0Input_];
                save_p1_input_reg_state_ = regs_[kP1Input_];
                port_made_int_ = port_num;
            } else {
                check_raise_int = true;
            }
            uint32_t pin_index = pins_to_index_[wire_num];
            bool pin_level = GetPinLevel(p_[port_num][pin_index]);
            UpdateInputPinLevel(port_num, pin_index, pin_level);
        }
    }

    if (check_raise_int && IsInputRegEqualInputPins()) {
        SetPinLevel(int_, true);
    }
    if (update_address) {
        SetDeviceAddress();
    }
    if (reset_values) {
        Reset();
    }
}

void PCA9539A::OnMasterRead(uint8_t device_address, iI2cSlaveBaseWriteStream& i2c_slave_write_stream) {
    while (!i2c_slave_write_stream.ReceivedNack()) {
        auto find_reg_data = regs_.find(reg_address_);
        if (find_reg_data == regs_.end()) {
            return;
        }
        uint8_t current_value = GetRegValue(reg_address_);
        i2c_slave_write_stream.Write(&current_value, 1);
        reg_address_ = (uint8_t)((reg_address_ ^ 0x1) % kRegsSize_);
    }
}

void PCA9539A::OnMasterWrite(uint8_t device_address, iI2cSlaveBaseReadStream& i2c_slave_read_stream) {
    if (is_reset_mode_) {
        std::cout << "Error: can't write to registers in a reset mode.\r\n" << std::endl;
    }

    // Read register address from master (command byte)
    uint8_t command_byte;
    size_t number_of_byte_recevied_from_master = i2c_slave_read_stream.ReadAndSendAck(&command_byte, 1);
    if (number_of_byte_recevied_from_master < 1) {
        return;
    }

    reg_address_ = command_byte;

    // Check if register address exist
    auto find_reg_data = regs_.find(reg_address_);
    if (find_reg_data == regs_.end()) {
        return;
    }

    uint8_t value;
    // Read data from master
    while (!i2c_slave_read_stream.ReceivedStop()) {
        number_of_byte_recevied_from_master = i2c_slave_read_stream.ReadAndSendAck(&value, 1);
        if (number_of_byte_recevied_from_master < 1) {
            return;
        }
        ack result = SetRegValue(reg_address_, value);
        if (!result) {
            return;
        }
        reg_address_ = (uint8_t)((reg_address_ ^ 0x1) % kRegsSize_);
    }
}