#include <Arduino.h>
#include <time.h>
#include <avr/wdt.h>
#include <avr/sleep.h>
#include "iot_bsp_system.h"
#include "iot_debug.h"

const char* iot_bsp_get_bsp_name()
{
    return "arduino";
}

const char* iot_bsp_get_bsp_version_string()
{
    return ARDUINO_VERSION;
}

void iot_bsp_system_reboot()
{
    wdt_enable(WDTO_15MS);
    while (true) {}
}

void iot_bsp_system_poweroff()
{
    // Power-off is not supported on Arduino Uno
}

iot_error_t iot_bsp_system_get_time_in_sec(char* buf, unsigned int buf_len)
{
    if (buf == NULL) {
        return IOT_ERROR_INVALID_ARGS;
    }

    time_t now = time(NULL);
    snprintf(buf, buf_len, "%ld", now);

    return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_system_set_time_in_sec(const char* time_in_sec)
{
    if (time_in_sec == NULL) {
        return IOT_ERROR_INVALID_ARGS;
    }

    // Setting time is not supported on Arduino Uno
    return IOT_ERROR_NOT_SUPPORTED;
}
