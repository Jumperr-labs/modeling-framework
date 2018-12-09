#include "ISM43362.h"
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>
#include <string>

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
    SpiSlaveConfig spi_config {};

    spi_config.mosi_pin_number = GetPinNumber("si");
    spi_config.miso_pin_number = GetPinNumber("so");
    spi_config.ss_pin_number = GetPinNumber("cs");
    spi_config.sclk_pin_number = GetPinNumber("sck");
    spi_config.supported_spi_modes = SPI_MODE_CPOL0_CPHA0;
    spi_config.max_frequency = 20000000;  // SPI Slave Clock rate: 20MHz max
    spi_config.bit_order = MSB_FIRST;

    spi_slave_ = CreateSpiSlave(spi_config);

//    SetPinChangeLevelEventCallback(GetPinNumber("WAKEUP"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "WAKEUP"));
//    SetPinChangeLevelEventCallback(GetPinNumber("RESET"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "RESET"));
//    SetPinChangeLevelEventCallback(GetPinNumber("EXTI1"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1, "CMD_DATA_RDY"));
//    SetPinChangeLevelEventCallback(GetPinNumber("UART3_TX"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1,"UART3_TX"));
//    SetPinChangeLevelEventCallback(GetPinNumber("UART3_RX"), std::bind(&ISM43362::OnPinChangeLevelEvent,this,std::placeholders::_1,"UART3_RX"));
//
//    Reset();
}

void ISM43362::OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications, std::string pin_name) {
    //WireLogicLevelEvent notification = notifications[0];
    //std::cout << "ISM43362::OnPinChangeLevelEvent: " << pin_name << " : " << notification.type << std::endl;
}

void ISM43362::OnRecv() {
    uint8_t rec_buf[4096] = {0};
    int size = TcpSocketRecv(id_2_socket_data_[current_id_].socket_fd, rec_buf, bytes_to_read_);
    (size == -1) ? SpiDataPhase("") : SpiDataPhase(std::string(rec_buf, rec_buf + size));
}

void ISM43362::OnSend(AtCommand& at_command, uint8_t* buf, int size) {
    int right = std::stoi(at_command.right_);  
    int sent_bytes = TcpSocketSend(id_2_socket_data_[current_id_].socket_fd, buf + size - right, right);
    SpiDataPhase(std::to_string(sent_bytes));
}

void ISM43362::OnDNSResolve(AtCommand& at_command, uint8_t* buf, int size) {
    char ip_string[50] = {0};
    struct in_addr ip;
    if (!DnsResolve(at_command.right_.c_str(), &ip)) {
//        std::cout << "Error: hostname could not be resolved" << std::endl;
        SpiDataPhase(ERROR);
        return;
    }

    strcpy(ip_string, inet_ntoa(ip));
    SpiDataPhase(ip_string);
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

    SpiDataPhase("");
}

/* https://www.inventeksys.com/iwin/at-cmds */
void ISM43362::HandleAtCommand(uint8_t* buf, int size) {
    AtCommand at_command = AtCommand(buf, size);
//    std::cout << "Command: " << at_command.full_command_ << std::endl;

    if (at_command.left_ == "I?") { /* Show Applications Information */
        SpiDataPhase("ISM43362-M3G-L44-SPI,C3.5.2.5.STM,v3.5.2,v1.4.0.rc1,v8.2.1,120000000,Inventek eS-WiFi");
    } else if (at_command.left_ == "C0") { /* Join a Network */
        SpiDataPhase("");
    } else if (at_command.left_ == "C1") { /* Set Network SSID */
        ap_ = at_command.right_;
        SpiDataPhase("");
    } else if (at_command.left_ == "C2") { /* Set Network Passphrase */
        password_ = at_command.right_;
        SpiDataPhase("");
    } else if (at_command.left_ == "C3") { /* Set Network Security Type */
        security_type_ = at_command.right_;
        SpiDataPhase("");
    } else if (at_command.left_ == "C4") { /* Set Network DHCP */
        dhcp_ = at_command.right_;
        SpiDataPhase("");
    } else if (at_command.left_ == "CD") { /* Disconnect from Network */
        id_2_socket_data_[current_id_] = SocketData();
        connected_ = "0";
        SpiDataPhase("");
    } else if (at_command.left_ == "CR") { /* Get RSSI of Associated Access Point */
        SpiDataPhase("-40"); // dummy value
    } else if (at_command.left_ == "CS") { /* Get Connection Status */
        SpiDataPhase(connected_);
    } else if (at_command.left_ == "C?") { /* Show Network Settings */
        SpiDataPhase(GetNetworkSetting());
    } else if (at_command.left_ == "D0") { /* DNS Lookup */
        OnDNSResolve(at_command, buf, size);
    } else if (at_command.left_ == "F0") { /* Scan for Network Access Points */
        SpiDataPhase("#001,\"DUMMY\",08:86:3B:2B:7E:2E,-40,54.0,Infrastructure, WPA2 AES,2.4GHz,1"); // dummy value
    } else if (at_command.left_ == "P0") { /* Set/Display Communication Socket */
        current_id_ = stoi(at_command.right_);
        SpiDataPhase("");
    } else if (at_command.left_ == "P1") { /* Set Transport Protocol */
        if (at_command.right_ != "0" && at_command.right_ != "3") /* TCP = 0, TCP-SSL = 3 */
            throw std::logic_error("ISM43362::HandleAtCommand: Unimplemented Protocol (UDP)");
        SpiDataPhase("");
    } else if (at_command.left_ == "P2") { /* Set Transport Local Port Number */
        SpiDataPhase("");
    } else if (at_command.left_ == "P3") { /* Set Transport Remote Host IP Address */
        id_2_socket_data_[current_id_].addr.sin_family = AF_INET;
        inet_pton(AF_INET, at_command.right_.c_str(), &(id_2_socket_data_[current_id_].addr.sin_addr));
        SpiDataPhase("");
    } else if (at_command.left_ == "P4") { /* Set Transport Remote Port Number */
        id_2_socket_data_[current_id_].addr.sin_port = htons(stoi(at_command.right_));
        SpiDataPhase("");
    } else if (at_command.left_ == "P6") { /* Stop/Start Transport Client */
        bool client_enable = at_command.right_[0] == '1';
        HandleAtCommandP6(client_enable);
    } else if (at_command.left_ == "P9") { /* SSL Certification Verification Level */
        is_ssl_ = at_command.right_ == "2";
        SpiDataPhase("");
    } else if (at_command.left_ == "PF") { /* Select Active Certificate Set */
        current_ssl_certificate_ = stoi(split(at_command.right_, ",")[1]) - 1;
        SpiDataPhase("");
    } else if (at_command.left_ == "PG") { /* Program CA, Certificate or key */
        OnSslCert(at_command, buf, size); //"PG=3,0,1733"
    } else if (at_command.left_ == "R0") {
        OnRecv();
    } else if (at_command.left_ == "R1") { /* Set Read Transport Packet Size (bytes) */
        bytes_to_read_ = std::stoi(at_command.right_);
        SpiDataPhase("");
    } else if (at_command.left_ == "R2") { /* Set Read Transport Timeout (ms) */
        int ms = stoi(at_command.right_);
        SetSocketRecvTimeout(id_2_socket_data_[current_id_].socket_fd, ms  / 1000, (ms * 1000) % 1000000);
        SpiDataPhase(""); // timeout == 1
    } else if (at_command.left_ == "S2") {
        int ms = stoi(at_command.right_);
        SetSocketSendTimeout(id_2_socket_data_[current_id_].socket_fd, ms  / 1000, (ms * 1000) % 1000000);
        SpiDataPhase(""); // timeout == 1
    } else if (at_command.left_ == "S3") { /* Write Transport Data */
        OnSend(at_command, buf, size);
    } else if (at_command.left_ == "Z5") { /* Get MAC Address */
        SpiDataPhase("");
    } else {
        std::cerr << "Unimplemented AT command: " << at_command.full_command_ << std::endl;
        SpiDataPhase("");
    }
}

void ISM43362::HandleAtCommandP6(bool client_enable) {
    bool result {};
    if (!client_enable) {
        result = SocketClose(id_2_socket_data_[current_id_].socket_fd);
    } else {
        SocketData &socket_data = id_2_socket_data_[current_id_];
        id_2_socket_data_[current_id_].socket_fd = TcpSocketCreate();
        SetSocketRecvTimeout(id_2_socket_data_[current_id_].socket_fd, 5, 0);
        SetSocketSendTimeout(id_2_socket_data_[current_id_].socket_fd, 5, 0);
        if (is_ssl_) {
            result = TcpSocketConnect(
                  socket_data.socket_fd,
                  &socket_data.addr,
                  true,
                  ssl_certificates_[current_ssl_certificate_].ca_cert,
                  ssl_certificates_[current_ssl_certificate_].client_cert,
                  ssl_certificates_[current_ssl_certificate_].client_key);
        } else {
            result = TcpSocketConnect(socket_data.socket_fd, &socket_data.addr, false, "", "", "");
        }
    }
    if (result == 0) connected_ = "1";
    result == 0 ? SpiDataPhase("") : SpiDataPhase(ERROR);
}

void ISM43362::Main() {
    Start();
}

void ISM43362::Stop() {
    should_stop_ = true;
}

// Reset all registers of ISM43362
// All regs reset values are zero except IODIR register, which should be 0xFF
void ISM43362::Reset() {
}

void ISM43362::CmdOrDataReadyPinSignal(transition_type_t type) {
    SetPinLevel(GetPinNumber("EXTI1"), type);
}

void ISM43362::Start() {
    /* The eS-WiFi module after power up or reset will raise CMD/DATA READY pin to signal that the first Data
     * Phase has started. In this mode, the SPI Host must fetch the cursor. The Host will initiate a SPI cycle
     * (lower SSN) and clock out 0x0A (Line Feed) until the CMD/DATA READY pin lowers signaling the end of the
     * Data Phase. The data received will be 0x0d (CR) 0x0A (LF) 0x3E (>) 0x20 (SP). */
    SpiDataPhase(START_CONN);
    while (!should_stop_)
        SpiCommandPhase();
}

/* The Command Phase indicates the eS-WiFi module is ready to accept an IWIN AT Command. */
void ISM43362::SpiCommandPhase() {
    StartCommandPhase();
    uint8_t buffer[4096];
    int bytes_read = spi_slave_->Transmit(buffer, nullptr , 4096);
    EndCommandPhase();
    if (bytes_read > 0)
        HandleAtCommand(buffer, bytes_read);
}

/* The Data Phase indicates the eS-WiFi module has data ready for the Host to read. */
void ISM43362::SpiDataPhase(std::string data) {
    if (data != START_CONN && data != ERROR) WarpDataToSend(data);
    uint8_t nak = 0x15;
    size_t size = data.size();
    if (size % 2 == 1) data += nak;
    uint8_t* buffer = (uint8_t *) data.c_str();
    size_t sent_bytes = 0;

    while (sent_bytes < size || should_stop_) {
        StartDataPhase();
        sent_bytes = spi_slave_->Transmit(nullptr, buffer, size);
        EndDataPhase();
    }

    while (spi_slave_->Transmit(nullptr, &nak, 1) != 0) {};  // wait until ss is inactive (sent_bytes == 0)
}

std::string ISM43362::GetNetworkSetting() {
    const std::string ip_version = "0";
    const std::string ip_address = "192.168.1.8";
    const std::string mask = "255.255.255.0";
    const std::string gateway = "192.168.1.1";
    const std::string dns = "192.168.1.1";
    const std::string retries = "5";
    const std::string auto_connect = "0";
    const std::string authentication = "0";
    const std::string country_code = "0";
    const std::string status = "1";
    return ap_ + "," + password_ + "," + security_type_ + "," + dhcp_ + "," + ip_version + "," + ip_address + "," +
          mask + "," + gateway + "," + dns + "," + dns + "," + retries + "," + auto_connect + "," + authentication +
          "," + country_code + "," + status;
}
