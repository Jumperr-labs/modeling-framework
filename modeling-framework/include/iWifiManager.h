#pragma once
#include <cstdint>

class iWifiManagerV1 {
  public:
    virtual void SetCurrentSocketID(int id) = 0;
    virtual void WifiSetPort(uint16_t) = 0;
    virtual void WifiSetIP(const char*) = 0;
    virtual void WifiConnect(bool isSSL) = 0;
    virtual int WifiSend(uint8_t* buf, int size) = 0;
    virtual int WifiRecv(uint8_t* buf, int size) = 0;
    virtual void IsSSL(bool isSSL_) = 0;
    virtual std::string GetLocalIP() = 0;   // Creat dummy socket in order to get the local IP
    virtual void SetSslCert(
        const char* SSL_CLIENT_RSA_CERT,
        const char* SSL_CLIENT_RSA_KEY,
        const char* SSL_CLIENT_RSA_CA_CERT,
        const char* SSL_CLIENT_RSA_CA_PATH) = 0;

    virtual void SetReadTimeout(int t) = 0;
    virtual void SetSendTimeout(int t) = 0;
    virtual int DnsResolve(const char* hostname, char* ip) = 0;
};

typedef iWifiManagerV1 iWifiManager;
