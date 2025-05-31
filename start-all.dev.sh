#!/bin/bash

set -e

echo "Starting all Whale Sentinel services (non-Docker mode)..."

# Start Redis in Docker if not already running
if [ "$(docker ps -q -f name=ws-redis)" ]; then
    echo "Redis container is already running."
else
    echo "Starting Redis container..."
    docker run -d \
        --name ws-redis \
        -p 6379:6379 \
        -v "$(pwd)/redis/redis.conf":/usr/local/etc/redis/redis.conf \
        redis:7.2 \
        redis-server /usr/local/etc/redis/redis.conf
fi

# Start Go-based services
echo "Starting Common Attack Detection (Go)..."
(cd whale-sentinel-common-attack-detection && go run main.go) &

echo "Starting Configuration Service (Go)..."
(cd whale-sentinel-configuration-service && go run main.go) &

echo "Starting Gateway Service (Go)..."
(cd whale-sentinel-gateway-service && go run main.go) &

# Activate Python environment
echo "Activating Python environment..."
source ~/Env/python3.9/bin/activate

# Start Python-based services
echo "Starting Web Attack Detection (Python)..."
(cd whale-sentinel-web-attack-detection && python app.py) &

echo "Starting DGA Detection (Python)..."
(cd whale-sentinel-dga-detection && python app.py) &

echo "All services started. Press Ctrl+C to stop."

# Wait for all background jobs
wait
