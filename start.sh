#!/bin/bash

mkdir -p /var/log/whale-sentinel/ws-services/ws-gateway-service
mkdir -p /var/log/whale-sentinel/ws-services/ws-configuration-service
mkdir -p /var/log/whale-sentinel/ws-services/ws-dga-detection
mkdir -p /var/log/whale-sentinel/ws-services/ws-common-attack-detection
mkdir -p /var/log/whale-sentinel/ws-services/ws-web-attack-detection

chmod 750 /var/log/whale-sentinel/

docker-compose up -d
