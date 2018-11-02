#pragma once
#include "ModelingFramework.h"
#include <map>
struct AtCommand;

struct SocketData {
    int32_t socket_fd;
    sockaddr_in addr;
};

struct SslData {
    std::string ca_cert {};
    std::string client_cert {};
    std::string client_key {};
};

class ISM43362 : public ExternalPeripheral {
  public:
    ISM43362();
    void Main() override;
    void Stop() override;

    ISM43362(const ISM43362&) = delete;
    ISM43362& operator=(const ISM43362&) = delete;

  private:
    void Reset();
    void HandleRead();
    void HandleWrite();
    void ResetWifi();
    void OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications, std::string pin_name);

    std::string buffer_{}; 
    void SpiWrite(const std::string& command);
    void SpiWrite(uint8_t* buf, int size);
    void OnRecv();
    void OnSend(AtCommand& at_command, uint8_t* buf, int size);
    void OnDNSResolve(AtCommand& at_command, uint8_t* buf, int size);
    void OnSslCert(AtCommand& at_command, uint8_t* buf, int size);
    // void SendTxEvent();
    void HandleAtCommand(uint8_t* buf, int size);
    void SpiWriteCommandAndOk(std::string data);

    iSpiSlaveV2* spi_slave_ {};

    int reset_done_ {};
    std::string ap_ {};
    std::string password_ {};
    bool should_stop_ {false};
    int current_id_ {-1};
    int current_ssl_certificate {-1};
    std::vector<SocketData> id_2_socket_data_;
    std::vector<SslData> ssl_certificates_;
};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new ISM43362();
}
