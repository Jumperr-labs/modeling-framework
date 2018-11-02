#include "ISM43362.h"
#include <netinet/in.h>
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

#define SPI_WRITE_OK    SpiWrite("\r\nOK\r\n> ")
#define SPI_WRITE_ERROR    SpiWrite("\r\nERROR")

#define SPI_WRITE_OK_INT(data)    SpiWrite(std::string("\r\n") + std::to_string(data) + "\r\nOK\r\n> ")

using namespace std;

struct AtCommand {
    AtCommand (uint8_t* buf, int size) {
        full_command_ = std::string((char*) buf, size );
        command_ = full_command_.substr(0, full_command_.find('\r'));

        right_ = left_ = command_;

        auto it = command_.find('=');

        if (it != std::string::npos) {
            right_ = command_.substr(it + 1, command_.size() - it);
            left_ = command_.substr(0, it);
        }
    }
    std::string full_command_{};
    std::string command_{};
    std::string right_{};
    std::string left_{};
};


ISM43362::ISM43362() : id_2_socket_data_(10), ssl_certificates_(3) {
    SpiSlaveConfig spi_config;

    spi_config.mosi_pin_number = GetPinNumber("si");
    spi_config.miso_pin_number = GetPinNumber("so");
    spi_config.ss_pin_number = GetPinNumber("cs");
    spi_config.sclk_pin_number = GetPinNumber("sck");
    spi_config.supported_spi_modes = SPI_MODE_CPOL0_CPHA0;
    spi_config.max_frequency = 10000000;
    spi_config.bit_order = MSB_FIRST;

    spi_slave_ = CreateSpiSlave(spi_config);

    SetPinChangeLevelEventCallback(GetPinNumber("WAKEUP"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "WAKEUP"));
    SetPinChangeLevelEventCallback(GetPinNumber("RESET"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "RESET"));
    SetPinChangeLevelEventCallback(GetPinNumber("EXTI1"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "EXTI1"));
    SetPinChangeLevelEventCallback(GetPinNumber("UART3_TX"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1,"UART3_TX"));
    SetPinChangeLevelEventCallback(GetPinNumber("UART3_RX"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1,"UART3_RX"));

    Reset();
}

void ISM43362::SpiWriteCommandAndOk(std::string data) {
    SpiWrite(std::string("\r\n") + data + "\r\nOK\r\n> ");
}

void ISM43362::OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications, std::string pin_name) {
    WireLogicLevelEvent notification = notifications[0];

    // std::cout << "ISM43362::OnPinChangeLevelEvent: " << pin_name << " : " << notification.type << std::endl;

    if (pin_name == "RESET") {
        reset_done_ += notification.type == FALLING ? 1 : 0; 
    }
}

void ISM43362::ResetWifi() {
    uint8_t prompt[] = {0x15, 0x15, '\r','\n','>',' ', };
    uint8_t opcode = 0;
    
    while (!should_stop_) {
        if(reset_done_ == 0) {
            continue;
        }

        spi_slave_->Transmit(nullptr, prompt, sizeof(prompt));
        SetPinLevel(GetPinNumber("EXTI1"), 0);

        spi_slave_->Transmit(nullptr, &opcode,1);
        SetPinLevel(GetPinNumber("EXTI1"), 1); //ready to receive

        return;
    }
}

void ISM43362::SpiWrite(const std::string& data) {
//    std::cout << "SpiWrite: " << data << std::endl;
    SpiWrite((uint8_t *)data.c_str(), data.size());
}

void ISM43362::SpiWrite(uint8_t* buf, int size) {
//    std::cout << "SpiWrite: " << buf << std::endl;
    // aligment
    if( size % 2 == 1) {
        buf[size] = 21;
        size++;
    }

    SetPinLevel(GetPinNumber("EXTI1"), 1);
    spi_slave_->Transmit(nullptr, buf, size);
    SetPinLevel(GetPinNumber("EXTI1"), 0);
}

void ISM43362::OnRecv() {
    uint8_t rec_buf[4096] = {0};
    memcpy(rec_buf, "\r\n", 2);
    int size = TcpSocketRecv(id_2_socket_data_[current_id_].socket_fd, rec_buf + 2, 4086);

    if (size == -1) {
        SpiWriteCommandAndOk("");
        return;
    }
    // else if (size < 0) {
    //     SpiWriteCommandAndOk("");
    //     return;
    // }
    // cout << std::string((char*)rec_buf + 2, size) << std::endl;

    memcpy(rec_buf + 2 + size, "\r\nOK\r\n> ", 8);
    
    SpiWrite(rec_buf, size + 10);
}

void ISM43362::OnSend(AtCommand& at_command, uint8_t* buf, int size) {
    int right = std::stoi(at_command.right_);  
    int sent_bytes = TcpSocketSend(id_2_socket_data_[current_id_].socket_fd, buf + size - right, right);
    SPI_WRITE_OK_INT(sent_bytes);
}

void ISM43362::OnDNSResolve(AtCommand& at_command, uint8_t* buf, int size) {
    char ip_string[50] = {0};
    struct in_addr ip;
    if (!DnsResolve(at_command.right_.c_str(), &ip)) {
//        std::cout << "Error: hostname could not be resolved" << std::endl;
        SPI_WRITE_ERROR;
        return;
    }

    strcpy(ip_string, inet_ntoa(ip));
    SpiWriteCommandAndOk(ip_string);
}

vector<string> split(const string& str, const string& delim) {
    vector<string> tokens;
    size_t prev = 0, pos = 0;
    do
    {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos-prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    }
    while (pos < str.length() && prev < str.length());
    return tokens;
}

void ISM43362::OnSslCert(AtCommand& at_command, uint8_t* buf, int size) {
    char* pCert = strchr((char*) buf, '\r');
    size = stoi(split(at_command.right_, ",")[2]);
    int index = stoi(split(at_command.right_, ",")[1]);
    int certificate = stoi(split(at_command.right_, ",")[0]);

    switch(index) {
        case 0: {
            ssl_certificates_[certificate - 1].ca_cert = std::string(pCert + 1, size);
            break;
        }
        case 1: {
            ssl_certificates_[certificate - 1].client_cert = std::string(pCert + 1, size);
            break;
        }
        case 2: {
            ssl_certificates_[certificate - 1].client_key = std::string(pCert + 1, size);
            break;
        }
    }

    SPI_WRITE_OK;
}

void ISM43362::HandleAtCommand(uint8_t* buf, int size) {
    AtCommand at_command = AtCommand(buf, size);
//    std::cout << "Command: " << at_command.full_command_ << std::endl;

    if (at_command.left_ == "I?") {
        SpiWriteCommandAndOk("ISM43362-M3G-L44-SPI,C3.5.2.5.STM,v3.5.2,v1.4.0.rc1,v8.2.1,120000000,Inventek eS-WiFi");
    } else if (at_command.left_ == "CS") {
        SPI_WRITE_OK_INT(0);
    } else if (at_command.left_ == "C1") {
        ap_ = at_command.right_;
        SPI_WRITE_OK; // C1=hello
    } else if (at_command.left_ == "C2") {
        password_ = at_command.right_;
        SPI_WRITE_OK; // C2=Bello123
    } else if (at_command.left_ == "C3") {
        SPI_WRITE_OK; // C3=3
    } else if (at_command.left_ == "C0") {
        SPI_WRITE_OK;
    } else if (at_command.left_ == "C?") {
        SpiWriteCommandAndOk(ap_ + "," + password_ + ",3,1,0,192.168.1.12,255.255.255.0,192.168.1.1,192.168.1.1,192.168.1.1,3,0,0,US,1");
    } else if (at_command.left_ == "D0") {
        OnDNSResolve(at_command, buf, size);
    } else if (at_command.left_ == "PF") {
        current_ssl_certificate = stoi(split(at_command.right_, ",")[1]) - 1;
        SPI_WRITE_OK; // "PF=0,3"
    } else if (at_command.left_ == "PG") {
        OnSslCert(at_command, buf, size);//"PG=3,0,1733"
    } else if (at_command.left_ == "P0") {
        current_id_ = stoi(at_command.right_);
        SPI_WRITE_OK;
    } else if (at_command.left_ == "P3") {
        id_2_socket_data_[current_id_].addr.sin_family = AF_INET;
        inet_pton(AF_INET, at_command.right_.c_str(), &(id_2_socket_data_[current_id_].addr.sin_addr));
        SPI_WRITE_OK;
    } else if (at_command.left_ == "P4") {
        id_2_socket_data_[current_id_].addr.sin_port = htons(stoi(at_command.right_));
        SPI_WRITE_OK;
    } else if (at_command.left_ == "P6") {
        bool result;
        if (at_command.right_[0] == '0') {
            result = SocketClose(id_2_socket_data_[current_id_].socket_fd);
        } else {
            SocketData &socket_data = id_2_socket_data_[current_id_];
            id_2_socket_data_[current_id_].socket_fd = TcpSocketCreate();
            SetSocketRecvTimeout(id_2_socket_data_[current_id_].socket_fd, 5, 0);
            SetSocketSendTimeout(id_2_socket_data_[current_id_].socket_fd, 5, 0);
            bool is_ssl = (current_ssl_certificate != -1);
            if (is_ssl) {
                result = TcpSocketConnect(
                        socket_data.socket_fd,
                        &socket_data.addr,
                        true,
                        ssl_certificates_[current_ssl_certificate].ca_cert,
                        ssl_certificates_[current_ssl_certificate].client_cert,
                        ssl_certificates_[current_ssl_certificate].client_key);
            } else {
                result = TcpSocketConnect(socket_data.socket_fd, &socket_data.addr, false, "", "", "");
            }
        }
        if (result == 0) {
            SPI_WRITE_OK;
        } else {
            SPI_WRITE_ERROR;
        }
    } else if (at_command.left_ == "S2") {
        int ms = stoi(at_command.right_);
        SetSocketSendTimeout(id_2_socket_data_[current_id_].socket_fd, ms  / 1000, (ms * 1000) % 1000000);
        SPI_WRITE_OK; // timeout == 1
    } else if (at_command.left_ == "S3") {
        OnSend(at_command, buf, size);
    } else if (at_command.left_ == "R2") {
        int ms = stoi(at_command.right_);
        SetSocketRecvTimeout(id_2_socket_data_[current_id_].socket_fd, ms  / 1000, (ms * 1000) % 1000000);
        SPI_WRITE_OK; // timeout == 1
    } else if (at_command.left_ == "R0") {
        OnRecv();
    } else {
        SPI_WRITE_OK;
    }

    // std::map<std::string, std::function<void(AtCommand&, uint8_t* , int)>> at_command_2_function_;

    // at_command_2_function_["S3"] = std::bind([&]() { OnSend(at_command, buf, size);});
    // at_command_2_function_["R0"] = std::bind([&]() {OnRecv(); }

    // auto it = at_command_2_function_.find(at_command.left_);
    // if(it == at_command_2_function_.end()){
    //     SPI_WRITE_OK;
    //     return;
    // }

    // it->second(at_command, buf, size);
}

void ISM43362::Main() {
    uint8_t buffer[4096];

    ResetWifi();

    while (!should_stop_) {
        int read = spi_slave_->Transmit(buffer, nullptr , 4096);

        if (read) {
            SetPinLevel(GetPinNumber("EXTI1"), 0);
            HandleAtCommand(buffer, read );
        }
        else {
            SetPinLevel(GetPinNumber("EXTI1"), 1); //ready to receive
        }
    }
}

void ISM43362::Stop() {
    should_stop_ = true;
}

// Reset all registers of ISM43362
// All regs reset values are zero except IODIR register, which should be 0xFF
void ISM43362::Reset() {
//    std::fill(registers_, registers_ + MCP_REGS, 0);
//    registers_[IODIR_ADDR] = 0XFF;

//   SpiWriteGPIO(0); // For reset output pin levels
}
