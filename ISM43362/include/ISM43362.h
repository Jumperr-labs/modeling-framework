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

static const std::string NEW_LINE = "\r\n";
static const std::string PROMPT = NEW_LINE + "> ";
static const std::string OK = NEW_LINE + "OK";
static const std::string ERROR = NEW_LINE + "ERROR";
static const std::string START_CONN = "\x15\x15" + PROMPT;

class ISM43362 : public ExternalPeripheral {
  public:
    ISM43362();
    void Main() override;
    void Stop() override;

    ISM43362(const ISM43362&) = delete;
    ISM43362& operator=(const ISM43362&) = delete;

  private:
    void MainLoop();
    void Reset();
    void HandleRead();
    void HandleWrite();
    void Start();
    void OnPinChangeLevelEvent(std::vector<WireLogicLevelEvent>& notifications, std::string pin_name);
    void SpiWrite(const std::string& command);
    void SpiWrite(uint8_t* buf, int size);
    void OnRecv();
    void OnSend(AtCommand& at_command, uint8_t* buf, int size);
    void OnDNSResolve(AtCommand& at_command, uint8_t* buf, int size);
    void OnSslCert(AtCommand& at_command, uint8_t* buf, int size);
    void HandleAtCommand(uint8_t* buf, int size);
    void HandleAtCommandP6(bool client_enable);
    void SpiWriteCommandAndOk(std::string data);
    void SpiDataPhase(std::string data);
    void SpiCommandPhase();
    void CmdOrDataReadyPinSignal(transition_type_t type);
    void StartCommandPhase() { CmdOrDataReadyPinSignal(RISING); }
    void EndCommandPhase() { CmdOrDataReadyPinSignal(FALLING); }
    void StartDataPhase() { CmdOrDataReadyPinSignal(RISING); }
    void EndDataPhase() { CmdOrDataReadyPinSignal(FALLING); }
    void WifiSendOk(transition_type_t type);
    void WarpDataToSend(std::string& data) { data = NEW_LINE + data + OK + PROMPT; }
    std::string GetNetworkSetting();

    iSpiSlaveV2* spi_slave_ {};
    bool reset_mode_ {};
    bool should_stop_ {};
    bool is_ssl_ {};
    std::string buffer_{};
    std::string ap_ {};
    std::string password_ {};
    std::string security_type_ {};
    std::string dhcp_ {};
    std::string connected_ {"0"};
    int current_id_ {-1};
    int current_ssl_certificate_ {-1};
    std::vector<SocketData> id_2_socket_data_;
    std::vector<SslData> ssl_certificates_;
    uint32_t bytes_to_read_ {};
};

DLL_EXPORT ExternalPeripheral *PeripheralFactory() {
    return new ISM43362();
}
