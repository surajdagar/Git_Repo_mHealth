#ifndef __MAGIC_CONNECT_H__
#define __MAGIC_CONNECT_H__

#include "mbed.h"

#define ETHERNET        1
#define WIFI_ESP8266    2
#define MESH_LOWPAN_ND  3
#define MESH_THREAD     4
#define WIFI_ODIN       5

#if MBED_CONF_APP_NETWORK_INTERFACE == WIFI_ESP8266
#include "ESP8266Interface.h"

#ifdef MBED_CONF_APP_ESP8266_DEBUG
ESP8266Interface wifi(MBED_CONF_APP_ESP8266_TX, MBED_CONF_APP_ESP8266_RX, MBED_CONF_APP_ESP8266_DEBUG);
#else
ESP8266Interface wifi(MBED_CONF_APP_ESP8266_TX, MBED_CONF_APP_ESP8266_RX);
#endif

#elif MBED_CONF_APP_NETWORK_INTERFACE == WIFI_ODIN
#include "OdinWiFiInterface.h"
OdinWiFiInterface wifi;
#elif MBED_CONF_APP_NETWORK_INTERFACE == ETHERNET
#include "EthernetInterface.h"
EthernetInterface eth;
#elif MBED_CONF_APP_NETWORK_INTERFACE == CELL
#include "C027Interface.h"
C027Interface cell;
#elif MBED_CONF_APP_NETWORK_INTERFACE == MESH_LOWPAN_ND
#define MESH
#include "NanostackInterface.h"
LoWPANNDInterface mesh;
#elif MBED_CONF_APP_NETWORK_INTERFACE == MESH_THREAD
#define MESH
#include "NanostackInterface.h"
ThreadInterface mesh;
#else
#error "No connectivity method chosen. Please add 'config.network-interfaces.value' to your mbed_app.json (see README.md for more information)."
#endif

#if defined(MESH)
#if MBED_CONF_APP_MESH_RADIO_TYPE == ATMEL
#include "NanostackRfPhyAtmel.h"
NanostackRfPhyAtmel rf_phy(ATMEL_SPI_MOSI, ATMEL_SPI_MISO, ATMEL_SPI_SCLK, ATMEL_SPI_CS,
                           ATMEL_SPI_RST, ATMEL_SPI_SLP, ATMEL_SPI_IRQ, ATMEL_I2C_SDA, ATMEL_I2C_SCL);
#elif MBED_CONF_APP_MESH_RADIO_TYPE == MCR20
#include "NanostackRfPhyMcr20a.h"
NanostackRfPhyMcr20a rf_phy(MCR20A_SPI_MOSI, MCR20A_SPI_MISO, MCR20A_SPI_SCLK, MCR20A_SPI_CS, MCR20A_SPI_RST, MCR20A_SPI_IRQ);
#elif MBED_CONF_APP_MESH_RADIO_TYPE == SPIRIT1
#include "NanostackRfPhySpirit1.h"
NanostackRfPhySpirit1 rf_phy(SPIRIT1_SPI_MOSI, SPIRIT1_SPI_MISO, SPIRIT1_SPI_SCLK,
			     SPIRIT1_DEV_IRQ, SPIRIT1_DEV_CS, SPIRIT1_DEV_SDN, SPIRIT1_BRD_LED);
#endif //MBED_CONF_APP_RADIO_TYPE
#endif //MESH

#ifndef MESH
// This is address to mbed Device Connector
#define MBED_SERVER_ADDRESS "coap://api.connector.mbed.com:5684"
#else
// This is address to mbed Device Connector
#define MBED_SERVER_ADDRESS "coaps://[2607:f0d0:2601:52::20]:5684"
#endif

#ifdef MBED_CONF_APP_ESP8266_SSID
#define MBED_CONF_APP_WIFI_SSID MBED_CONF_APP_ESP8266_SSID
#endif

#ifdef MBED_CONF_APP_ESP8266_PASSWORD
#define MBED_CONF_APP_WIFI_PASSWORD MBED_CONF_APP_ESP8266_PASSWORD
#endif


NetworkInterface* easy_connect(bool log_messages = false) {
    NetworkInterface* network_interface = 0;
    int connect_success = -1;
#if MBED_CONF_APP_NETWORK_INTERFACE == WIFI_ESP8266
    if (log_messages) {
        printf("[EasyConnect] Using WiFi (ESP8266) \n");
        printf("[EasyConnect] Connecting to WiFi %s\n", MBED_CONF_APP_WIFI_SSID);
    }
    connect_success = wifi.connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
    network_interface = &wifi;
#elif MBED_CONF_APP_NETWORK_INTERFACE == WIFI_ODIN
    if (log_messages) {
        printf("[EasyConnect] Using WiFi (ODIN) \n");
        printf("[EasyConnect] Connecting to WiFi %s\n", MBED_CONF_APP_WIFI_SSID);
    }
    connect_success = wifi.connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD, NSAPI_SECURITY_WPA_WPA2);
    network_interface = &wifi;
#elif MBED_CONF_APP_NETWORK_INTERFACE == ETHERNET
    if (log_messages) {
        printf("[EasyConnect] Using Ethernet\n");
    }
    connect_success = eth.connect();
    network_interface = &eth;
#elif MBED_CONF_APP_NETWORK_INTERFACE == CELL
    if (log_messages) {
        printf("[EasyConnect] Using CELL\n");
    }
    connect_success = cell.connect(MBED_CONF_APP_APN);
    network_interface = &cell;
#endif
#ifdef MESH
    if (log_messages) {
        printf("[EasyConnect] Using Mesh\n");
        printf("[EasyConnect] Connecting to Mesh..\n");
    }
    mesh.initialize(&rf_phy);
    connect_success = mesh.connect();
    network_interface = &mesh;
#endif
    if(connect_success == 0) {
        if (log_messages) {
            printf("[EasyConnect] Connected to Network successfully\n");
        }
    } else {
        if (log_messages) {
            printf("[EasyConnect] Connection to Network Failed %d!\n", connect_success);
        }
        return NULL;
    }
    const char *ip_addr  = network_interface->get_ip_address();
    //const char *mac_addr = network_interface->get_mac_address();
    if (ip_addr == NULL) {
        if (log_messages) {
            printf("[EasyConnect] ERROR - No IP address\n");
        }
        return NULL;
    }
    /**
    if (mac_addr == NULL) {
        if (log_messages) {
            printf("[EasyConnect] ERROR - No MAC address\n");
        }
        return NULL;
    }
    **/
    if (log_messages) {
        printf("[EasyConnect] IP address %s\n", ip_addr);
        //printf("[EasyConnect] MAC address %s\n", mac_addr);
    }
    return network_interface;
}

#endif // __MAGIC_CONNECT_H__
