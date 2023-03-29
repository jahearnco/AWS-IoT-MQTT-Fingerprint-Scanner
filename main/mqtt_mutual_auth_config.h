/*
 * AWS IoT Device SDK for Embedded C 202103.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @brief The name of the MQTT library used and its version, following an "@"
 * symbol.
 */
#include "core_mqtt.h"
#define MQTT_LIB    "core-mqtt@" MQTT_LIBRARY_VERSION



/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* POSIX includes. */
#include <unistd.h>


/* MQTT API headers. */
#include "core_mqtt.h"
#include "core_mqtt_state.h"

/* OpenSSL sockets transport implementation. */
#include "network_transport.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* Clock for timer. */
#include "clock.h"

#ifdef CONFIG_EXAMPLE_USE_ESP_SECURE_CERT_MGR
    #include "esp_secure_cert_read.h"
#endif

#ifndef MQTT_MUTUAL_AUTH_CONFIG_H_
#define MQTT_MUTUAL_AUTH_CONFIG_H_
#endif /* ifndef MQTT_MUTUAL_AUTH_CONFIG_H_ */

/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the Demo. */
#ifndef LIBRARY_LOG_NAME
    #define LIBRARY_LOG_NAME     "MQTT_DEMO"
#endif
#ifndef LIBRARY_LOG_LEVEL
    #define LIBRARY_LOG_LEVEL    LOG_INFO
#endif

//#include "logging_stack.h"

/************ End of logging configuration ****************/


/**
 * @brief Details of the MQTT broker to connect to.
 *
 * @note Your AWS IoT Core endpoint can be found in the AWS IoT console under
 * Settings/Custom Endpoint, or using the describe-endpoint API.
 *
 *const char AWS_IOT_ENDPOINT[] = "a1ztyso0l848eo-ats.iot.us-west-2.amazonaws.com";
 */
#ifndef AWS_IOT_ENDPOINT
    #define AWS_IOT_ENDPOINT    CONFIG_MQTT_BROKER_ENDPOINT
#endif

/**
 * @brief AWS IoT MQTT broker port number.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 */
#ifndef AWS_MQTT_PORT
    #define AWS_MQTT_PORT    ( CONFIG_MQTT_BROKER_PORT )
#endif

/**
 * @brief The username value for authenticating client to MQTT broker when
 * username/password based client authentication is used.
 *
 * Refer to the AWS IoT documentation below for details regarding client
 * authentication with a username and password.
 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
 * As mentioned in the link above, an authorizer setup needs to be done to use
 * username/password based client authentication.
 *
 * @note AWS IoT message broker requires either a set of client certificate/private key
 * or username/password to authenticate the client. If this config is defined,
 * the username and password will be used instead of the client certificate and
 * private key for client authentication.
 *
 * #define CLIENT_USERNAME    "...insert here..."
 */

/**
 * @brief The password value for authenticating client to MQTT broker when
 * username/password based client authentication is used.
 *
 * Refer to the AWS IoT documentation below for details regarding client
 * authentication with a username and password.
 * https://docs.aws.amazon.com/iot/latest/developerguide/custom-authentication.html
 * As mentioned in the link above, an authorizer setup needs to be done to use
 * username/password based client authentication.
 *
 * @note AWS IoT message broker requires either a set of client certificate/private key
 * or username/password to authenticate the client.
 *
 * #define CLIENT_PASSWORD    "...insert here..."
 */

/**
 * @brief MQTT client identifier.
 *
 * No two clients may use the same client identifier simultaneously.
 */
#ifndef CLIENT_IDENTIFIER
    #define CLIENT_IDENTIFIER    CONFIG_MQTT_CLIENT_IDENTIFIER
#endif

/**
 * @brief MQTT topic
 *
 * defined w sdkconfig
 */
#ifndef MQTT_TOPIC
    #define MQTT_TOPIC CONFIG_MQTT_TOPIC
#endif


/**
 * @brief Size of the network buffer for MQTT packets.
 */
#define NETWORK_BUFFER_SIZE       ( CONFIG_MQTT_NETWORK_BUFFER_SIZE )

/**
 * @brief The name of the operating system that the application is running on.
 * The current value is given as an example. Please update for your specific
 * operating system.
 */
#define OS_NAME                   "FreeRTOS"

/**
 * @brief The version of the operating system that the application is running
 * on. The current value is given as an example. Please update for your specific
 * operating system version.
 */
#define OS_VERSION                tskKERNEL_VERSION_NUMBER

/**
 * @brief The name of the hardware platform the application is running on. The
 * current value is given as an example. Please update for your specific
 * hardware platform.
 */
#define HARDWARE_PLATFORM_NAME    CONFIG_HARDWARE_PLATFORM_NAME

#ifndef CLIENT_IDENTIFIER
    #error "Please define a unique client identifier, CLIENT_IDENTIFIER, in menuconfig"
#endif

/* The AWS IoT message broker requires either a set of client certificate/private key
 * or username/password to authenticate the client. */
#ifdef CLIENT_USERNAME
/* If a username is defined, a client password also would need to be defined for
 * client authentication. */
    #ifndef CLIENT_PASSWORD
        #error "Please define client password(CLIENT_PASSWORD) in demo_config.h for client authentication based on username/password."
    #endif
/* AWS IoT MQTT broker port needs to be 443 for client authentication based on
 * username/password. */
    #if AWS_MQTT_PORT != 443
        #error "Broker port, AWS_MQTT_PORT, should be defined as 443 in demo_config.h for client authentication based on username/password."
    #endif
#else /* !CLIENT_USERNAME */
/*
 *!!! Please note democonfigCLIENT_PRIVATE_KEY_PEM in used for
 *!!! convenience of demonstration only.  Production devices should
 *!!! store keys securely, such as within a secure element.
 */
    #ifndef CONFIG_EXAMPLE_USE_ESP_SECURE_CERT_MGR
        extern const char client_cert_start[] asm("_binary_client_crt_start");
        extern const char client_cert_end[] asm("_binary_client_crt_end");
        extern const char client_key_start[] asm("_binary_client_key_start");
        extern const char client_key_end[] asm("_binary_client_key_end");
    #endif /* CONFIG_EXAMPLE_USE_ESP_SECURE_CERT_MGR */
#endif /* CLIENT_USERNAME */

extern const char root_cert_auth_start[]   asm("_binary_root_cert_auth_crt_start");
extern const char root_cert_auth_end[]   asm("_binary_root_cert_auth_crt_end");

/**
 * These configuration settings are required to run the mutual auth demo.
 * Throw compilation error if the below configs are not defined.
 */

/**
 * @brief Length of MQTT server host name.
 */
#define AWS_IOT_ENDPOINT_LENGTH         ( ( uint16_t ) ( sizeof( AWS_IOT_ENDPOINT ) - 1 ) )

/**
 * @brief Length of client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH        ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief ALPN (Application-Layer Protocol Negotiation) protocol name for AWS IoT MQTT.
 *
 * This will be used if the AWS_MQTT_PORT is configured as 443 for AWS IoT MQTT broker.
 * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
 * in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
#define AWS_IOT_MQTT_ALPN               "x-amzn-mqtt-ca"

/**
 * @brief Length of ALPN protocol name.
 */
#define AWS_IOT_MQTT_ALPN_LENGTH        ( ( uint16_t ) ( sizeof( AWS_IOT_MQTT_ALPN ) - 1 ) )

/**
 * @brief This is the ALPN (Application-Layer Protocol Negotiation) string
 * required by AWS IoT for password-based authentication using TCP port 443.
 */
#define AWS_IOT_PASSWORD_ALPN           "mqtt"

/**
 * @brief Length of password ALPN.
 */
#define AWS_IOT_PASSWORD_ALPN_LENGTH    ( ( uint16_t ) ( sizeof( AWS_IOT_PASSWORD_ALPN ) - 1 ) )


/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milli seconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                  ( 1000U )

/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define MQTT_EXAMPLE_TOPIC                  CLIENT_IDENTIFIER "/" MQTT_TOPIC

/**
 * @brief Length of client MQTT topic.
 */
#define MQTT_EXAMPLE_TOPIC_LENGTH           ( ( uint16_t ) ( sizeof( MQTT_EXAMPLE_TOPIC ) - 1 ) )

/**
 * @brief The MQTT message published in this example.
 */
#define MQTT_MESSAGE                "A Lovely Day!"

/**
 * @brief The length of the MQTT message published in this example.
 */
#define MQTT_MESSAGE_LENGTH         ( ( uint16_t ) ( sizeof( MQTT_MESSAGE ) - 1 ) )

/**
 * @brief Maximum number of outgoing publishes maintained in the application
 * until an ack is received from the broker.
 */
#define MAX_OUTGOING_PUBLISHES              ( 5U )

/**
 * @brief Invalid packet identifier for the MQTT packets. Zero is always an
 * invalid packet identifier as per MQTT 3.1.1 spec.
 */
#define MQTT_PACKET_ID_INVALID              ( ( uint16_t ) 0U )

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS        ( 5000U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 *  between two Control Packets.
 *
 *  It is the responsibility of the Client to ensure that the interval between
 *  Control Packets being sent does not exceed the this Keep Alive value. In the
 *  absence of sending any other Control Packets, the Client MUST send a
 *  PINGREQ Packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS    ( 60U )

/**
 * @brief Delay between MQTT publishes in seconds.
 */
#define DELAY_BETWEEN_PUBLISHES_SECONDS     ( 1U )

/**
 * @brief Number of PUBLISH messages sent per iteration.
 */
#define MQTT_PUBLISH_COUNT_PER_LOOP         ( 5U )

/**
 * @brief Delay in seconds between two iterations of subscribePublishLoop().
 */
#define MQTT_SUBPUB_LOOP_DELAY_SECONDS      ( 5U )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS      ( 1500U )

/**
 * @brief The MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING                      "?SDK=" OS_NAME "&Version=" OS_VERSION "&Platform=" HARDWARE_PLATFORM_NAME "&MQTTLib=" MQTT_LIB

/**
 * @brief The length of the MQTT metrics string expected by AWS IoT.
 */
#define METRICS_STRING_LENGTH               ( ( uint16_t ) ( sizeof( METRICS_STRING ) - 1 ) )


#ifdef CLIENT_USERNAME

/**
 * @brief Append the username with the metrics string if #CLIENT_USERNAME is defined.
 *
 * This is to support both metrics reporting and username/password based client
 * authentication by AWS IoT.
 */
    #define CLIENT_USERNAME_WITH_METRICS    CLIENT_USERNAME METRICS_STRING
#endif

/**
 * @brief The length of the outgoing publish records array used by the coreMQTT
 * library to track QoS > 0 packet ACKS for outgoing publishes.
 */
#define OUTGOING_PUBLISH_RECORD_LEN    ( 10U )

/**
 * @brief The length of the incoming publish records array used by the coreMQTT
 * library to track QoS > 0 packet ACKS for incoming publishes.
 */
#define INCOMING_PUBLISH_RECORD_LEN    ( 10U )

