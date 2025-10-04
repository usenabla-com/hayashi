# Hayashi - Architecture Boundary Diagrams as Code

![](./diagram.png)

A Rust-based REST API service that transforms Terraform state files into detailed FedRAMP-aligned architecture boundary diagrams using AI-enhanced Mermaid diagram generation.

## Overview

Hayashi is a web service that parses Terraform state files and generates visual architecture diagrams with security and compliance boundaries. It leverages Cloudflare Workers AI to create human-friendly diagrams that meet FedRAMP, NIST 800-53, and other compliance framework requirements.

## Features

- 🔄 **Automatic Diagram Generation**: Parse Terraform state files and generate Mermaid flowchart diagrams
- 🔒 **Security Boundary Visualization**: Clearly delineate FedRAMP authorization boundaries and trust zones
- 📋 **Compliance Controls**: Annotate resources with relevant NIST 800-53 controls (SC-7, AU-2, AC-6, CM-2, etc.)
- 🏗️ **Architecture Tiers**: Automatically organize resources into public, application, and data tiers
- 🎨 **Smart Styling**: Color-coded boundaries and security zones with AWS service icons
- 🤖 **AI-Enhanced**: Uses Cloudflare Workers AI to generate clean, readable diagrams

## Installation

### Prerequisites

- Rust 1.70+
- Cloudflare account with Workers AI access

### Build from Source

```bash
git clone https://github.com/yourusername/hayashi.git
cd hayashi
cargo build --release
```

### Environment Variables

```bash
export CLOUDFLARE_ACCOUNT_ID="your-account-id"
export CLOUDFLARE_API_TOKEN="your-api-token"
```

## Usage

### Starting the API Server

```bash
cargo run --release
```

The API server will start on `http://0.0.0.0:3000`

### API Endpoint

**POST** `/v1/diagram`

Generate a Mermaid architecture diagram from a Terraform state file.

#### Request Body

```json
{
  "name": "Production Environment",
  "statefile_path": "/path/to/terraform.tfstate",
  "model": "@cf/openai/gpt-oss-120b",
  "api_key": "optional-override-api-key"
}
```

#### Parameters

- `name` (required): Title for the generated diagram
- `statefile_path` (required): Path to the Terraform state file
- `model` (optional): Cloudflare Workers AI model to use (defaults to `@cf/openai/gpt-oss-120b`)
- `api_key` (optional): Override the default Cloudflare API token

#### Response

```json
{
  "mermaid_content": "flowchart TB\n    ...",
  "metadata": {
    "generated_at": "2025-10-04T12:34:56Z",
    "node_count": 25,
    "edge_count": 18,
    "title": "Production Environment"
  }
}
```

### Example Usage with curl

```bash
curl -X POST http://localhost:3000/v1/diagram \
  -H "Content-Type: application/json" \
  -d '{
    "name": "FedRAMP Production Boundary",
    "statefile_path": "./terraform.tfstate"
  }'
```

## Supported Resources

Hayashi automatically categorizes and visualizes a wide range of AWS resources including:

- **Networking**: VPC, Internet Gateway, NAT Gateway, Load Balancers, Security Groups, NACLs
- **Compute**: ECS, EKS, EC2, Lambda, Auto Scaling Groups
- **Storage**: S3, EFS, EBS
- **Database**: RDS, DynamoDB, ElastiCache, DocumentDB, Neptune
- **Security**: KMS, IAM, GuardDuty, Security Hub, WAF
- **Monitoring**: CloudTrail, GuardDuty, Config, CloudWatch, VPC Flow Logs

## How It Works

1. **State File Parsing**: Reads and parses Terraform state files to extract infrastructure resources
2. **Resource Graph Building**: Constructs a directed graph of resources and their relationships
3. **Trust Zone Classification**: Automatically categorizes resources into:
   - Identity & Access Management plane
   - Key Management plane
   - Audit & Monitoring plane
   - Network boundaries (VPCs with tiered subnets)
   - External interfaces
4. **Subnet Tier Detection**: Intelligently classifies subnets as Public, Private-App, Private-DB, or Management
5. **AI Enhancement**: Sends the base diagram structure to Cloudflare Workers AI for human-friendly formatting
6. **FedRAMP Compliance**: Adds NIST 800-53 control annotations, encryption labels, and authorization boundaries

## Output Format

The API returns Mermaid flowchart syntax with:
- **FedRAMP Authorization Boundary** as the main container
- **Trust zone subgraphs** (Security Services, VPCs, Network Tiers)
- **AWS service icons** from icon.icepanel.io and cloudflare CDN
- **Encryption annotations** (🔒 EBS-CMK, 🔒 KMS, etc.)
- **NIST control references** (SC-7, AU-2, CM-2, etc.)
- **Color-coded styling** for different security zones

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with Rust 🦀
- Diagram rendering powered by Mermaid.js
- Icons from AWS Architecture Icons and IcePanel
