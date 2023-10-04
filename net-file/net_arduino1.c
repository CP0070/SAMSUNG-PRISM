#include <Arduino.h>
#include <Ethernet.h>
#include <EthernetClient.h>
#include <EthernetServer.h>
#include <EthernetUdp.h>
#include <SPI.h>
#include <WiFi101.h>
#include <WiFiClient.h>
#include <WiFiSSLClient.h>
#include <WiFiUdp.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <mbedtls/rsa.h>
#include <cerrno>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>
#include <cstring>
#include <stdio.h>



#include "iot_main.h"
#include "iot_debug.h"

#define NETWORK_VALID_SUCCESS 0
#define NETWORK_VALID_ERROR 1
#define MAX_SOCK_NUM 4


iot_error_t _iot_net_check_interface() {
  Ethernet.init(10); // Ethernet shield initialization
  if (Ethernet.linkStatus() == LinkOFF) {
    return NETWORK_VALID_ERROR; // Network interface is not valid
  }
  return NETWORK_VALID_SUCCESS;
}

void _iot_net_show_status(int socket) {
  EthernetClient client;
  bool isReadable = client.available();
  bool isWritable = client.connected();
  int socketError = client.getSocketNumber();
  int systemErrno = errno;

  Serial.print("Readability: ");
  Serial.println(isReadable ? "Readable" : "Not Readable");
  
  Serial.print("Writability: ");
  Serial.println(isWritable ? "Writable" : "Not Writable");

  Serial.print("Socket Error: ");
  Serial.println(socketError);

  Serial.print("System Errno: ");
  Serial.println(systemErrno);
}


int _iot_net_select(EthernetClient& client, unsigned long timeout) {
  struct timeval tv;
  fd_set readSet;
  int socketNumber = client.getSocketNumber();

  // Clear the read set and add the socket to it
  FD_ZERO (&readSet);
  FD_SET(socketNumber, &readSet);

  // Set the timeout value
  tv.tv_sec = timeout / 1000;
  tv.tv_usec = (timeout % 1000) * 1000;

  // Perform the select operation
  int selectResult = select(socketNumber + 1, &readSet, NULL, NULL, &tv);

  if (selectResult == -1) {
    // Error occurred during select
    return errno;
  } else if (selectResult == 0) {
    // Timeout occurred
    return ETIMEDOUT;
  } else {
    // Data is available
    return 0;
  }
}

void _iot_net_cleanup_platform_context() {
 Ethernet.maintain();
}


static int _iot_net_tls_asn1_write_int(unsigned char **p, unsigned char *start, const mbedtls_mpi *X)
{
    int ret;
    size_t len = mbedtls_mpi_size(X);
    unsigned char *end = start + len;

    *p = start;

    while (start < end)
    {
        --end;
        *start++ = *end;
    }

    return (int)len;
}


static int _iot_net_tls_raw_to_der(const unsigned char *raw_key, size_t raw_key_len, unsigned char *der, size_t der_max_len, size_t *der_len)
{
    int ret;
    mbedtls_pk_context key;

    mbedtls_pk_init(&key);

    ret = mbedtls_pk_parse_key(&key, raw_key, raw_key_len, NULL, 0);
    if (ret != 0)
    {
        mbedtls_pk_free(&key);
        return ret;
    }

    ret = mbedtls_pk_write_key_der(&key, der, der_max_len);
    if (ret >= 0)
    {
        *der_len = ret;
    }

    mbedtls_pk_free(&key);
    return ret;
}
static int _iot_net_tls_external_sign(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, unsigned char *sig, size_t *sig_len) {
    // Your implementation for signing the hash goes here

    // Example implementation using mbedtls_rsa_pkcs1_sign()
    mbedtls_rsa_context *rsa_ctx = (mbedtls_rsa_context *)ctx;

    int ret = mbedtls_rsa_pkcs1_sign(rsa_ctx, NULL, MBEDTLS_RSA_PRIVATE, md_alg, (unsigned int)hash_len, hash, sig);

    if (ret == 0) {
        *sig_len = mbedtls_rsa_get_len(rsa_ctx);
    }

    return ret;
}

// Function to resume the TLS operation after an asynchronous signing process
int _iot_net_tls_external_resume(mbedtls_ssl_context *ssl) {
 mbedtls_ssl_session_reset(ssl);

  // Resume the TLS operation
  int ret = mbedtls_ssl_handshake(ssl);

  return ret;}

// Function to cancel the ongoing asynchronous signing process
int _iot_net_tls_external_cancel(mbedtls_ssl_context *ssl) {
 int result = mbedtls_ssl_session_reset(ssl);
  
  // Check for errors
  if (result != 0) {
    // An error occurred while canceling the signing process
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error canceling signing process: ");
    Serial.println(error_buf);
    return result; // Return the error code
  }
  
  // Signing process canceled successfully
  return 0; 
}

// Function to initialize the mbedTLS SSL configuration for external private key operations
int iot_net_tls_external_private(mbedtls_ssl_context *ssl, const mbedtls_pk_context *pk, const mbedtls_x509_crt *ca) {
  int result = mbedtls_ssl_conf_own_cert(ssl, ca, pk);
  
  // Check for errors
  if (result != 0) {
    // An error occurred while setting the private key and certificate chain
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error initializing external private key: ");
    Serial.println(error_buf);
    return result; // Return the error code
  }
  
  // Function to establish a TLS connection
int _iot_net_tls_connect(mbedtls_ssl_context *ssl, const char *host, const char *port, const mbedtls_x509_crt *ca)
 {
  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  // Initialize the required mbedtls structures
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(ssl);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  // Seed the random number generator
  int result = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
  if (result != 0) {
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error seeding random number generator: ");
    Serial.println(error_buf);
    return result;
  }

  // Setup SSL/TLS configuration
  result = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (result != 0) {
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error setting up SSL configuration: ");
    Serial.println(error_buf);
    return result;
  }

  // Load trusted CA root certificate
  result = mbedtls_ssl_conf_ca_chain(&ssl_conf, ca, nullptr);
  if (result != 0) {
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error loading CA root certificate: ");
    Serial.println(error_buf);
    return result;
  }

  // Connect to the server
  result = mbedtls_net_connect(&server_fd, host, port, MBEDTLS_NET_PROTO_TCP);
  if (result != 0) {
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error connecting to the server: ");
    Serial.println(error_buf);
    return result;
  }

  // Setup SSL/TLS context
  result = mbedtls_ssl_setup(ssl, &ssl_conf);
  if (result != 0) {
    char error_buf[100];
    mbedtls_strerror(result, error_buf, sizeof(error_buf));
    Serial.print("Error setting up SSL context: ");
    Serial.println(error_buf);
    return result;
  }

  // Set socket file descriptor for SSL/TLS context
  mbedtls_ssl_set_bio(ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

  // Perform the TLS handshake
  while ((result = mbedtls_ssl_handshake(ssl)) != 0) {
    if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
      char error_buf[100];
      mbedtls_strerror(result, error_buf, sizeof(error_buf));
      Serial.print("Error performing TLS handshake: ");
      Serial.println(error_buf);
      return result;
    }
  }

  // Verify the server certificate
  result = mbedtls_ssl_get_verify_result(ssl);
  if (result != 0) {
    char error_buf[100];
    mbedtls_x509_crt_verify_info(error_buf, sizeof(error_buf), "  ! ", result);
    Serial.print("Certificate verification failed: ");
    Serial.println(error_buf);
    return result;
  }

  // TLS connection established successfully
  return 0;
}

iot_error_t _iot_net_tcp_keepalive(iot_net_interface_t *net, unsigned int idle, unsigned int count, unsigned int intval)
 {
  iot_error_t err;
  int socket;
  int keepAlive = 1;
  int ret;

  err = _iot_net_check_interface(net);
  if (err) 
  {
    return err;
  }

  socket = net->context.server_fd.fd;
  ret = setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &keepAlive, sizeof(keepAlive));
  if (ret) 
  {
    Serial.println("fail to set KEEPALIVE error");
    return IOT_ERROR_BAD_REQ;
  }
  ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
  if (ret) 
  {
    Serial.println("fail to set KEEPALIVEIDLE error")
    return IOT_ERROR_BAD_REQ
  }
  ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count))
  if (ret) 
  {
    Serial.println("fail to set KEEPALIVECOUNT error");
    return IOT_ERROR_BAD_REQ;
  }
  ret = setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, &intval, sizeof(intval))
  if (ret) {
    Serial.println("fail to set KEEPALIVEINTERVAL error");
    return IOT_ERROR_BAD_REQ;
  }

  return IOT_ERROR_NONE
}

void _iot_net_tls_disconnect(iot_net_interface_t *net) {
  _iot_net_cleanup_platform_context(net);
}

int _iot_net_tls_read(iot_net_interface_t *net, unsigned char *buf, size_t len, iot_os_timer timer) {
  int recvLen = 0, ret = 0;

  if (_iot_net_check_interface(net)) {
    return 0;
  }

  if (buf == NULL || timer == NULL) {
    return -1;
  }

  if (len == 0) {
    return 0;
  }

  mbedtls_ssl_conf_read_timeout(&net->context.conf, (uint32_t)iot_os_timer_left_ms(timer));

  do {
    ret = mbedtls_ssl_read(&net->context.ssl, buf, len);

    if (ret > 0) {
      recvLen += ret
    } 
    else {
      if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
          (ret != MBEDTLS_ERR_SSL_WANT_WRITE) &&
          (ret != MBEDTLS_ERR_SSL_TIMEOUT)) {
        Serial.printf("mbedtls_ssl_read = -0x%04X\n", -ret);
        return ret;
      }
    }
  } while (recvLen < len && !iot_os_timer_isexpired(timer))

  return recvLen
}

int _iot_net_tls_write(iot_net_interface_t *net, unsigned char *buf, int len, iot_os_timer timer) {
  int sentLen = 0, ret = 0;

  if (_iot_net_check_interface(net)) {
    return 0;
  }

  do {
    ret = mbedtls_ssl_write(&net->context.ssl, buf + sentLen, (size_t)len - sentLen);

    if (ret > 0) {
      sentLen += ret;
    } else {
      if ((ret != MBEDTLS_ERR_SSL_WANT_READ) &&
          (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
        Serial.printf("mbedtls_ssl_write = -0x%04X\n", -ret);
        return ret;
      }
    }
  } while (sentLen < len && !iot_os_timer_isexpired(timer));

  return sentLen
}

iot_error_t iot_net_init(iot_net_interface_t *net) {
  iot_error_t err;

  err = _iot_net_check_interface(net);
  if (err) {
    return err;
  }

  net->connect = _iot_net_tls_connect;
  net->tcp_keepalive = _iot_net_tcp_keepalive;
  net->disconnect = _iot_net_tls_disconnect;
  net->select = _iot_net_select;
  net->read = _iot_net_tls_read;
  net->write = _iot_net_tls_write;
  net->show_status = _iot_net_show_status;

  return IOT_ERROR_NONE;
}
