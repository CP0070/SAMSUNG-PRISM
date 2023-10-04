#include "iot_bsp_random.h"
#include <Arduino.h>

unsigned int iot_bsp_random()
{
    unsigned int lower = random();
    unsigned int upper = random();
    return (upper << 16) | lower;
}
