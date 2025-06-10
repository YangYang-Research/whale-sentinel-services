# Whale Sentinel Services

[![Horusec Security Scan](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/horusec-scan.yml/badge.svg?branch=main)](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/horusec-scan.yml)
[![CodeQL Advanced](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/codeql.yml)

| No. | Service | Language | Image |  Tag |
| --- | -------- | ------- | ------- |  ----- |
| 1 | whale-sentinel-common-attack-detection | Go1.24.0 | [whale-sentinel-common-attack-detection](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-common-attack-detection) |  0.1.0 |
| 2 | whale-sentinel-configuration-service | Go1.24.0 | [whale-sentinel-configuration-service](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-configuration-service) | 0.1.0 |
| 3 | whale-sentinel-dga-detection | Python3.12 | [whale-sentinel-dga-detection](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-dga-detection) | 0.1.0 |
| 4 | whale-sentinel-web-attack-detection | Python3.12 | [whale-sentinel-web-attack-detection](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-web-attack-detection) | 0.1.0 |
| 5 | whale-sentinel-gateway-service | Go1.24.0 | [whale-sentinel-gateway-service](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-gateway-service) | 0.1.0 |

# 🚀 Usage Guide

## 🛠️ Preparation 

1. Create an IAM User

- Go to AWS IAM console and create a new IAM user.

- Assign sufficient permissions for Secrets Manager, EC2, RDS.

- Generate and securely store the following credentials:

    - AWS_ACCESS_KEY_ID

    - AWS_SECRET_ACCESS_KEY

2. Create AWS Secret

- In AWS Secrets Manager, create a new secret named: AWS_SECRET_NAME

- Add the following keys to your secret:

    - WHALE_SENTINEL_AGENT_SECRET_KEY_NAME

    - WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME

    - WHALE_SENTINEL_CONTROLLER_SECRET_KEY_NAME

## 🚦 Starting Whale Sentinel Services

1. Download & Unzip the Latest Package Release for Deployment

- Navigate to the [Releases](https://github.com/YangYang-Research/whale-sentinel-services/releases) page.

- Download the package ZIP and extract it.

2. Configure the Docker Environment

- Rename the sample compose file: `mv docker-compose.example.yml docker-compose.yml`

- (Recommended) Change the default Redis password in redis/redis.conf and update docker-compose.yml accordingly.

3. Apply Your Configuration

- Replace all placeholder values in docker-compose.yml and other config files (fluent-bit.conf, etc.) with your actual environment-specific values (e.g., AWS credentials, secret names, ports).

4. Start the Services

- Run the following command to launch all services in the background: `docker-compose up -d`

