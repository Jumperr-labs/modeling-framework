#pragma once
#include <cstdint>

enum class ShortPinNumber{
    PIN0 = 0,
    PIN1 = 1
};

class iShort {
  public:
    virtual void SetPin(ShortPinNumber pin_number, uint32_t pin) = 0;
    virtual void DisableShort() = 0;
};
