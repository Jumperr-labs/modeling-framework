#pragma once
#include "ModelingFramework.h"

typedef std::vector<WireLogicLevelEvent> WireLogicLevelEvent_t;


class iJemuV1 {
  public:
    virtual int GetPinNumber(const char *pin_name) = 0;
    virtual iSpiSlave* CreateSpiSlave(SpiSlaveConfig &spi_config) = 0;

    virtual bool GetPinLevel(int pin_number) = 0;
    virtual void SetPinLevel(int pin_number, bool pin_level) = 0;
    virtual int AddTimedCallback(uint64_t ns, void (*callback)(int id), bool run_once) = 0;
    virtual void CancelTimedCallback(int id) = 0;
    virtual void UpdateTimedCallback(int id, uint64_t ns) = 0;
    virtual int32_t GetNextInt32FromDataGenerator(const char* name) = 0;
    virtual double GetNextDoubleFromDataGenerator(const char* name) = 0;
    virtual int16_t GetNextInt16FromDataGenerator(const char* name) = 0;
    virtual uint8_t GetNextUInt8FromDataGenerator(const char* name) = 0;
    virtual double GetCachedValueFromDataGenerator(const char* name) = 0;
};

class iJemuV2 : public iJemuV1 {
  public:
    virtual void SetMultiplePinsLevel(WireChange* pin_changes_ptr, size_t size) = 0;
    virtual void SetPinDirection(uint32_t pin_id,  pin_direction_t direction, bool pullup) = 0;
    virtual void SetPinChangeLevelEventCallback(uint32_t pin_id, iPinChangeLevelEventCallback *callback) = 0;

    virtual iI2cSlave* CreateI2cSlave() = 0;
};

class iJemuV3 : public iJemuV2 {
  public:

    virtual iShort* CreateShort() = 0;
    virtual iWifiManager* CreateWifiManager() = 0;
    virtual bool HasDataGenerator(const char* name) = 0;
    virtual iUartDevice* CreateUartDevice(UartConfig &uartConfig) = 0;
    virtual int TcpSocketCreate() = 0;
    virtual int TcpSocketConnect(int fd, const struct sockaddr_in *address, bool is_ssl, const char* ca_cert, const char* client_cert, const char* client_key) = 0;
    virtual int TcpSocketRecv(int fd, void* buffer, size_t size) = 0;
    virtual int TcpSocketSend(int fd, void* buffer, size_t size) = 0;
    virtual bool DnsResolve(const char* hostname, struct in_addr *ip) = 0;
    virtual int SocketClose(int fd) = 0;
    virtual void SetSocketSendTimeout(int fd, int s, int us) = 0;
    virtual void SetSocketRecvTimeout(int fd, int s, int us) = 0;
};

typedef iJemuV3 iJemuInterface;
