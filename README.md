# 🐋 Whale Sentinel Services

[![Horusec Security Scan](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/horusec-scan.yml/badge.svg?branch=main)](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/horusec-scan.yml)
[![CodeQL Advanced](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/YangYang-Research/whale-sentinel-services/actions/workflows/codeql.yml)

## 🔧 Overview

**Whale Sentinel Services** is the centralized backend of the Whale Sentinel threat detection ecosystem. These microservices perform real-time threat detection, agent coordination, DGA analysis, and web attack inspection, enabling deep security observability and active protection for connected applications.

---

## 🧩 Services & Images

| No. | Service Name                              | Language   | Docker Image                                                                                                                  | Version |
|-----|-------------------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------|---------|
| 1   | `whale-sentinel-common-attack-detection`  | Go 1.24.0  | [Image](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-common-attack-detection)      | 0.1.3   |
| 2   | `whale-sentinel-configuration-service`    | Go 1.24.0  | [Image](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-configuration-service)        | 0.1.3   |
| 3   | `whale-sentinel-dga-detection`            | Python 3.12| [Image](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-dga-detection)                | 0.1.3   |
| 4   | `whale-sentinel-web-attack-detection`     | Python 3.12| [Image](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-web-attack-detection)         | 0.1.3   |
| 5   | `whale-sentinel-gateway-service`          | Go 1.24.0  | [Image](https://gallery.ecr.aws/j8d4r7c5/whale-sentinel/whale-sentinel-services/whale-sentinel-gateway-service)              | 0.1.3   |

---

## 🚀 Getting Started

### 🛠️ Prerequisites

1. **Create an IAM User**
   - Go to AWS IAM console and create a user with permissions for Secrets Manager, EC2, and RDS.
   - Generate and securely store:
     - `AWS_ACCESS_KEY_ID`
     - `AWS_SECRET_ACCESS_KEY`

2. **Create a Secret in AWS Secrets Manager**
   - Secret name: `AWS_SECRET_NAME`
   - Keys to include:
     - `WHALE_SENTINEL_AGENT_SECRET_KEY_NAME`
     - `WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME`
     - `WHALE_SENTINEL_CONTROLLER_SECRET_KEY_NAME`

---

### 📦 Deployment Steps

#### 1. Download the Deployment Package
- Visit the [Releases](https://github.com/YangYang-Research/whale-sentinel-services/releases) page.
- Download the latest deployment package and extract it.

#### 2. Configure Docker Compose
```bash
mv docker-compose.example.yml docker-compose.yml
```
- *(Optional)* Update the default Redis password in `redis/redis.conf` and `docker-compose.yml`.

#### 3. Replace Config Placeholders

Update the following values in `docker-compose.yml`, `fluent-bit.conf`, and `.env`:

| Key | Description | Example |
|-----|-------------|---------|
| `AWS_REGION` | AWS deployment region | `us-west-2` |
| `AWS_ACCESS_KEY_ID` | IAM access key | `AKIA...` |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key | `abc123...` |
| `AWS_SECRET_NAME` | Secret name in Secrets Manager | `whale-prod-secret` |
| `WHALE_SENTINEL_AGENT_SECRET_KEY_NAME` | Agent secret key field | `agent-secret-key` |
| `WHALE_SENTINEL_SERVICE_SECRET_KEY_NAME` | Service secret key field | `service-secret-key` |
| `WHALE_SENTINEL_CONTROLLER_SECRET_KEY_NAME` | Controller secret key field | `controller-secret-key` |
| `REDIS_PASSWORD` | Redis access password | `supersecurepass` |
| `WS_CONTROLLER_PROCESSOR_URL` | Whale MDP endpoint URL | `http://controller:8080/processor` |
| `OPENSEARCH_ENDPOINT` | OpenSearch endpoint | `https://search-xyz.us-west-2.es.amazonaws.com` |
| `OPENSEARCH_USERNAME` | OpenSearch user | `admin` |
| `OPENSEARCH_PASSWORD` | OpenSearch password | `password123` |

#### 4. Start All Services

```bash
docker-compose up -d
```

---

## 🤝 Contributing

We welcome contributions and feedback. Please fork the repository and open a pull request with your suggested changes.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🛡️ Security & Reporting

If you discover a vulnerability, please report it responsibly via GitHub Issues or contact the maintainers privately.