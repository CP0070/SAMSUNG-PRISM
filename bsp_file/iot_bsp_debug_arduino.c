#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <Arduino.h>
#include <MemoryFree.h>
#include "iot_bsp_debug.h"

extern  Serial;

typedef enum {
    IOT_DEBUG_LEVEL_ERROR = 0,
    IOT_DEBUG_LEVEL_WARN,
    IOT_DEBUG_LEVEL_INFO,
    IOT_DEBUG_LEVEL_DEBUG
} iot_debug_level_t;

void iot_bsp_debug(iot_debug_level_t level, const char* tag, const char* fmt, ...)
{
    char* buf;
    int ret;
    va_list va;

    va_start(va, fmt);
    ret = vsnprintf(NULL, 0, fmt, va);
    va_end(va);

    buf = (char*)malloc(ret + 1);

    va_start(va, fmt);
    ret = vsnprintf(buf, ret + 1, fmt, va);
    va_end(va);

    if (level == IOT_DEBUG_LEVEL_ERROR) {
        Serial.print("[ERROR] ");
    } else if (level == IOT_DEBUG_LEVEL_WARN) {
        Serial.print("[WARN] ");
    } else if (level == IOT_DEBUG_LEVEL_INFO) {
        Serial.print("[INFO] ");
    } else if (level == IOT_DEBUG_LEVEL_DEBUG) {
        Serial.print("[DEBUG] ");
    } else {
        Serial.print("[UNKNOWN] ");
    }

    Serial.print(tag);
    Serial.print(": ");
    Serial.println(buf);

    free(buf);
}
static unsigned int _iot_bsp_debug_get_free_heap_size(void)
{
  return freeMemory();
}
static unsigned int _iot_bsp_debug_get_minimum_free_heap_size(void)
{
    return freeMemory();
}
static unsigned int _iot_bsp_debug_get_maximum_heap_size(void)
{
    int allocated_bytes = 0;
    int* ptr;

    while (true) {
        ptr = (int*) malloc(sizeof(int));
        if (ptr != NULL) {
            allocated_bytes += sizeof(int);
            free(ptr);
        } else {
            break;
        }
    }

    return allocated_bytes;
}
void iot_bsp_debug_check_heap(const char* tag, const char* func, const int line, const char* fmt, ...)
{
	static int count = 0;
	char* buf;
	int ret;
	va_list va;

	va_start(va, fmt);
	ret = vsnprintf(buf, 0, fmt, va);
	va_end(va);

	buf = (char*)malloc(ret + 1);

	va_start(va, fmt);
	ret = vsnprintf(buf, ret + 1, fmt, va);
	va_end(va);

	if (count == 0) {
		Serial.print(func);
		Serial.print("(");
		Serial.print(line);
		Serial.print(") > [MEMCHK][");
		Serial.print(count);
		Serial.print("] Heap total size : ");
		Serial.println(_iot_bsp_debug_get_maximum_heap_size());
	}

	Serial.print(func);
	Serial.print("(");
	Serial.print(line);
	Serial.print(") > [MEMCHK][");
	Serial.print(++count);
	Serial.print("][");
	Serial.print(buf);
	Serial.print("] CU:");
	
	Serial.print(", CR:");
	
	Serial.print(", PU:");
	
	Serial.print(", PR:");
	

	if (buf != NULL) {
		free(buf);
	}
}

