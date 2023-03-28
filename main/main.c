/* tls-mutual-auth example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "r307.h"

uint8_t esp_chip_id[6];                                     //++ Array to get Chip ID
char mac_address[20];                                       //++ Array to store Mac Address

char default_address[4] = {0xFF, 0xFF, 0xFF, 0xFF};         //++ Default Module Address is FF:FF:FF:FF
char default_password[4] = {0x00, 0x00, 0x00, 0x00};        //++ Default Module Password is 00:00:00:00

int aws_iot_demo_main( int argc, char ** argv );

static const char *TAG = "MQTT_EXAMPLE";

/*
 * Prototypes for the demos that can be started from this project.  Note the
 * MQTT demo is not actually started until the network is already.
 */

void app_main()
{
    ESP_LOGI(TAG, "[APP] Startup..");
    ESP_LOGI(TAG, "[APP] Free memory: %"PRIu32" bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());

    esp_log_level_set("*", ESP_LOG_INFO);
    
    r307_init();                                            //++ Initializing UART for r307 Module

    //esp_efuse_mac_get_default(esp_chip_id);
    sprintf(mac_address, "%02x:%02x:%02x:%02x:%02x:%02x", esp_chip_id[0], esp_chip_id[1], esp_chip_id[2], esp_chip_id[3], esp_chip_id[4], esp_chip_id[5]);
    printf("MAC Address is %s\n", mac_address);             //++ Get the MAC Address of current ESP32

    uint8_t confirmation_code = 0;
    confirmation_code = VfyPwd(default_address, default_password);      //++ Performs Password Verification with Fingerprint Module

    if(confirmation_code == 0x00)
    {
        printf("R307 FINGERPRINT MODULE DETECTED\n");
    }


    /* Initialize NVS partition */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated
         * and needs to be erased */
        ESP_ERROR_CHECK(nvs_flash_erase());

        /* Retry nvs_flash_init */
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    aws_iot_demo_main(0,NULL);
}
