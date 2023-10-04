#include <Arduino.h>
#include <EEPROM.h> 

#include "iot_bsp_nv_data.h"
#include "iot_debug.h"

enum iot_nvd_t {
  IOT_NVD_WIFI_PROV_STATUS,
  IOT_NVD_AP_SSID,
  IOT_NVD_AP_PASS,
  IOT_NVD_AP_BSSID,
  IOT_NVD_AP_AUTH_TYPE,
  IOT_NVD_CLOUD_PROV_STATUS,
  IOT_NVD_SERVER_URL,
  IOT_NVD_SERVER_PORT,
  IOT_NVD_LABEL,
  IOT_NVD_DEVICE_ID,
  IOT_NVD_MISC_INFO,
  IOT_NVD_PRIVATE_KEY,
  IOT_NVD_PUBLIC_KEY,
  IOT_NVD_ROOT_CA_CERT,
  IOT_NVD_SUB_CA_CERT,
  IOT_NVD_DEVICE_CERT,
  IOT_NVD_SERIAL_NUM,
  IOT_NVD_MAX
};

const char* iot_bsp_nv_get_data_path(iot_nvd_t nv_type) {
  if (nv_type < 0 || nv_type > IOT_NVD_MAX) {
    return NULL; 
  }

  switch (nv_type) {
    case IOT_NVD_WIFI_PROV_STATUS:
      return "WifiProvStatus";
    case IOT_NVD_AP_SSID:
      return "IotAPSSID";
    case IOT_NVD_AP_PASS:
      return "IotAPPASS";
    case IOT_NVD_AP_BSSID:
      return "IotAPBSSID";
    case IOT_NVD_AP_AUTH_TYPE:
      return "IotAPAuthType";
    case IOT_NVD_CLOUD_PROV_STATUS:
      return "CloudProvStatus";
    case IOT_NVD_SERVER_URL:
      return "ServerURL";
    case IOT_NVD_SERVER_PORT:
      return "ServerPort";
    case IOT_NVD_LABEL:
      return "Label";
    case IOT_NVD_DEVICE_ID:
      return "DeviceID";
    case IOT_NVD_MISC_INFO:
      return "MiscInfo";
    case IOT_NVD_PRIVATE_KEY:
      return "PrivateKey";
    case IOT_NVD_PUBLIC_KEY:
      return "PublicKey";
    case IOT_NVD_ROOT_CA_CERT:
      return "RootCert";
    case IOT_NVD_SUB_CA_CERT:
      return "SubCert";
    case IOT_NVD_DEVICE_CERT:
      return "DeviceCert";
    case IOT_NVD_SERIAL_NUM:
      return "SerialNum";
    default:
      return NULL;
  }
}
