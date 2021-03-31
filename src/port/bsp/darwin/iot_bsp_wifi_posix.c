/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>

#include <netinet/in.h>
#include <net/route.h>
#include <sys/types.h>
#include <pwd.h>

#include "iot_debug.h"
#include "iot_bsp_wifi.h"

#define IFACE_NAME	"wlan0"

static int _create_socket()
{
    int sockfd = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        IOT_ERROR("Can't get socket (%d, %s)", errno, strerror(errno));
        return -errno;
    }
    return sockfd;
}

iot_error_t iot_bsp_wifi_init()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	return 0;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	struct ifaddrs *ifs, *cur;
	iot_error_t err = IOT_ERROR_READ_FAIL;

	if (getifaddrs(&ifs) == 0) {
		for (cur = ifs; cur; cur = cur->ifa_next) {
            if (cur->ifa_addr->sa_family == AF_LINK && cur->ifa_addr) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)cur->ifa_addr;
				memcpy(wifi_mac->addr, LLADDR(sdl), sizeof(wifi_mac->addr));
				err = IOT_ERROR_NONE;
                break;
            }
        }
		freeifaddrs(ifs);
	}
	return err;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}
