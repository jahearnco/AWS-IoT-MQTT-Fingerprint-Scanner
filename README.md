| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- |

# AWS IoT ESP32-MQTT r307 Fingerprint Sensor Module
The Following Code is a Library for interfacing r307 Fingerprint Module with ESP32 on Embedded C Language

(See the README.md file in the upper level 'examples' directory for more information about examples.)

This example connects to the broker test.mosquitto.org using ssl transport with client certificate and as a demonstration subscribes/unsubscribes and send a message on certain topic.
(Please note that the public broker is maintained by the community so may not be always available, for details please visit http://test.mosquitto.org)

It uses ESP-MQTT library which implements mqtt client to connect to mqtt broker.

## How to use example

### Hardware Required

This example can be executed on any ESP32 board, the only required interface is WiFi and connection to internet.

### Configure the project

* Open the project configuration menu (`idf.py menuconfig`)
* Configure Wi-Fi or Ethernet under "Example Connection Configuration" menu. See "Establishing Wi-Fi or Ethernet Connection" section in [examples/protocols/README.md](../../README.md) for more details.

* Generate your client keys and certificate

Navigate to the main directory

```
cd main
```

Generate a client key and a CSR. When you are generating the CSR, do not use the default values. At a minimum, the CSR must include the Country, Organisation and Common Name fields.

```
openssl genrsa -out client.key
openssl req -out client.csr -key client.key -new
```

Paste the generated CSR in the [Mosquitto test certificate signer](https://test.mosquitto.org/ssl/index.php), click Submit and copy the downloaded `client.crt` in the `main` directory.

Please note, that the supplied files `client.crt` and `client.key` in the `main` directory are only placeholders for your client certificate and key (i.e. the example "as is" would compile but would not connect to the broker)

The server certificate `mosquitto.org.crt` can be downloaded in pem format from [mosquitto.org.crt](https://test.mosquitto.org/ssl/mosquitto.org.crt).

### Build and Flash

Build the project and flash it to the board, then run monitor tool to view serial output:

```
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

## Example Output

```
I (3714) event: sta ip: 192.168.0.139, mask: 255.255.255.0, gw: 192.168.0.2
I (3714) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (3964) MQTT_CLIENT: Sending MQTT CONNECT message, type: 1, id: 0000
I (4164) MQTTS_EXAMPLE: MQTT_EVENT_CONNECTED
I (4174) MQTTS_EXAMPLE: sent publish successful, msg_id=41464
I (4174) MQTTS_EXAMPLE: sent subscribe successful, msg_id=17886
I (4174) MQTTS_EXAMPLE: sent subscribe successful, msg_id=42970
I (4184) MQTTS_EXAMPLE: sent unsubscribe successful, msg_id=50241
I (4314) MQTTS_EXAMPLE: MQTT_EVENT_PUBLISHED, msg_id=41464
I (4484) MQTTS_EXAMPLE: MQTT_EVENT_SUBSCRIBED, msg_id=17886
I (4484) MQTTS_EXAMPLE: sent publish successful, msg_id=0
I (4684) MQTTS_EXAMPLE: MQTT_EVENT_SUBSCRIBED, msg_id=42970
I (4684) MQTTS_EXAMPLE: sent publish successful, msg_id=0
I (4884) MQTT_CLIENT: deliver_publish, message_length_read=19, message_length=19
I (4884) MQTTS_EXAMPLE: MQTT_EVENT_DATA
TOPIC=/topic/qos0
DATA=data
I (5194) MQTT_CLIENT: deliver_publish, message_length_read=19, message_length=19
I (5194) MQTTS_EXAMPLE: MQTT_EVENT_DATA
TOPIC=/topic/qos0
DATA=data
```

# GPIO Functions:
| ESP32 Devkit v1   | r307 Fingerprint Sensor |
| ------------- | ------------- |
| VIN pin | Pin 1 |
| GND pin | Pin 2 |
| GPIO 16 | Pin 3 |
| GPIO 17 | Pin 4 |

* Pin 5 and Pin 6 of the sensor can be opened ( No Connection )

# Connection Diagram:
![ESP32_R307_Connection](https://user-images.githubusercontent.com/99990377/171999044-11c50e19-c3a8-41ce-922c-179af355bffc.png)

# Understanding the Flow:
* This code is developed for ESP32 on Embedded C Language.
* There are 2 files you need to import which are going to be the library for interfacing ESP32 with R307 Sensor Module.
* R307 Fingerprint Sensor by default runs on UART Baud : **57600, with 8 data bits, 1 stop bit and no partiy.**
* Once **"r307_init()"** is called, that shall initialize UART ESP32 with the set parameters.
* Further there are 3 sections for the following library :
  * check_sum()
  * r307_reponse()
  * r307_response_parser()
* The **check_sum()** performs checksum modulo 256 on **Package Identifier, Package Length, Instruction Code and ( if used ) Packet Data** like new address, new password, etc.
* **r307_reponse()** function is responsible to receive package responses sent via the sensor module to ESP32.
* Lastly, **r307_response_parser()** function has the prime role of parsing every response received from the fingerprint sensor.
* There are several functions involved, total 22 for this library currently, that perform various tasks like setting new module address & new module password, reading system parameters, capturing or verifying or storing finger, etc.
* All these functions are written as per their names given in the user manual for r307 fingerprint module.
* Last but not the least, this repo is a library and doesn't have any example codes yet although every component you need to build a program for yourself can be easily done as comments and briefing is done for every code of line used.
* Please note, everytime you use any function to perform a task, you will have to provide the 32-bits Module address ( Default Address : 0xFF, 0xFF, 0xFF, 0xFF & Default Password : 0x00, 0x00, 0x00, 0x00 )
* Also note that any extra packet data if being used has to be declared in an char array with hex values as the data.

# Conclusion:
* Interfacing ESP32 with r307 Fingerprint Sensor wasn't the easiest or the most difficult but I did encountered lot of odds to develop the library on C as whole of the internet happens to use Arduino IDE.
* Examples codes are not yet available, but if I work on them in future then will surely commit the same.
* There are two functions missing : "WriteNotepad" & "ReadNotepad". I tried but couldn't crack them, so will commit the same whenever possible in future.
* Do share with others and I hope you all like it :-D

# Reference Material:
* https://www.openhacks.com/uploadsproductos/r307_fingerprint_module_user_manual.pdf


