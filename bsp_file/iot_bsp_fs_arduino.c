#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <EEPROM.h>
#include <AESLib.h>


#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"

#define FILE_MAGIC_NUMBER_LEN 6
#define EEPROM_FILE_START_ADDR FILE_MAGIC_NUMBER_LEN
#define AES_BLOCK_SIZE 16
#define EEPROM_SIZE 1024



const uint8_t encryption_key[AES_BLOCK_SIZE] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
const uint32_t FILE_MAGIC_NUMBER = 0xDEADBEEF;

typedef struct {
  uint8_t magicNumber[FILE_MAGIC_NUMBER_LEN];
  uint8_t length;
}FileHeader;


iot_error_t iot_bsp_fs_init() {
  EEPROM.begin(EEPROM_SIZE);

  // Initialize other necessary components or configurations

  return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit() {
  // Deinitialize any components or configurations used by the file system

  EEPROM.end();

  return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle) {
  if (handle == NULL) {
    return IOT_ERROR_INVALID_ARGS;
  }

  handle->fd = 0;
  strncpy(handle->filename, filename, sizeof(handle->filename));

  if (mode == FS_READONLY) {
    EEPROM.begin(EEPROM_SIZE);
  } else {
    EEPROM.beginWrite(EEPROM_SIZE);
  }

  return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t* length) {
  FileHeader header;
  EEPROM.get(EEPROM_FILE_START_ADDR, header);

  if (memcmp(header.magicNumber, FILE_MAGIC_NUMBER, FILE_MAGIC_NUMBER_LEN) != 0) {
    IOT_DEBUG("File not found: %s", handle.filename);
    EEPROM.end();
    return IOT_ERROR_FS_NO_FILE;
  }

  if (*length < header.length) {
    IOT_ERROR("Buffer length is not enough (%d < %d)", *length, header.length);
    EEPROM.end();
    return IOT_ERROR_FS_READ_FAIL;
  }

  for (size_t i = 0; i < header.length; i++) {
    buffer[i] = EEPROM.read(EEPROM_FILE_START_ADDR + sizeof(header) + i);
  }
  *length = header.length;

  EEPROM.end();

  return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length) {
  if (length > EEPROM.length() - EEPROM_FILE_START_ADDR - sizeof(FileHeader)) {
    IOT_ERROR("Data length exceeds EEPROM size");
    return IOT_ERROR_FS_WRITE_FAIL;
  }

  FileHeader header;
  memcpy(header.magicNumber, FILE_MAGIC_NUMBER, FILE_MAGIC_NUMBER_LEN);
  header.length = length;

  EEPROM.put(EEPROM_FILE_START_ADDR, header);
  for (unsigned int i = 0; i < length; i++) {
    EEPROM.write(EEPROM_FILE_START_ADDR + sizeof(header));
  }}
iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle) {
  EEPROM.end();

  return IOT_ERROR_NONE;
}


