# Contextual Cloud Steganography (CCS) Framework

**Breaking the Capacity-Security Trade-Off in Cloud Steganography**

## 📖 Overview

**Contextual Cloud Steganography (CCS)** is a novel framework that transforms cloud storage into a high-capacity, secure covert communication channel. Unlike traditional steganography methods that modify file contents, CCS leverages the **contextual ordering** of files within cloud folders to embed secret information, achieving:

- **3.2× to 4.3× higher capacity** than state-of-the-art base-B encoding methods
- **Protocol-dependent security** that makes message extraction computationally infeasible without the contextual protocol
- **Complete file integrity preservation** ensuring inherent resistance to statistical steganalysis
- **Logarithmic capacity scaling** with folder size: `C = ⌊log₂(M)⌋` bits per folder

This framework implements the complete system described in the paper "Contextual Cloud Steganography: Breaking the Capacity-Security Trade-Off" (IEEE Transactions on Information Forensics and Security, 2024).

## 🚀 Key Features

### 🔒 Enhanced Security
- **480+ contextual protocol combinations** for protocol-based security
- **AES-256 encryption** for message confidentiality
- **HMAC-SHA256 verification** for file integrity
- **Zero-knowledge architecture** where possible

### 📈 Superior Capacity
- **Logarithmic scaling**: 10 bits per folder for 1024 files (vs. 3 bits for base-8)
- **Adaptive segmentation** based on folder capacity
- **Multi-folder parallel embedding** for large payloads

### ⚡ High Performance
- **Optimized extraction** with precomputed hash maps (7.4× faster)
- **Cloud-agnostic design** (Google Drive, Dropbox, OneDrive)
- **Sub-second processing** for folders up to 10,000 files

### 🛡️ Enterprise Ready
- **Fault-tolerant extraction** with graceful degradation
- **Proactive change detection** in dynamic environments
- **Comprehensive error recovery** (93-98% success rates)
- **Audit-compliant operations**

## 📊 Theoretical Advantages

| Metric | Traditional Base-B | CCS (Proposed) | Improvement |
|--------|-------------------|----------------|-------------|
| Capacity per folder | Constant (3-6 bits) | `⌊log₂(M)⌋` bits | **3.2× to 4.3×** |
| Security layers | Cryptographic only | Protocol + Crypto | **Additional dimension** |
| Detectability | Medium (statistical) | Low (no modification) | **Inherently resistant** |
| Scalability | Constant | Logarithmic | **Grows with storage** |

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐
│     Sender      │────▶│   Cloud Storage │
│   (Alice)       │     │  (Cover Folders)│
└─────────────────┘     └─────────────────┘
         │                       │
         │  Pre-shared Protocol  │       ┌─────────────────┐
         └───────────────────────┘──────▶│    Receiver     │
                                          │     (Bob)       │
                                          └─────────────────┘
```

### Core Components:
1. **Contextual Protocol (𝒫)**: Deterministic file ordering based on metadata
2. **Cover Folders**: Source directories with legitimate files
3. **Stego-Folder**: Output directory containing embedded message
4. **Stego-Key**: Credentials + protocol + encryption key

## 🔧 Installation

### Prerequisites
- Python 3.8+
- Cloud storage accounts (Google Drive, Dropbox, or OneDrive)
- API credentials for cloud providers

### Quick Install
```bash
# Clone repository
git clone https://github.com/smossebo/CSS.git
cd ccs

# Install dependencies
pip install -r requirements.txt


### Docker Installation
```bash
# Build Docker image
docker build -t ccs-framework .

# Run container
docker run -it --rm ccs-framework
```

## 📚 Usage Examples

### Basic Embedding and Extraction
```python
from ccs.core import CCSEmbedder, CCSExtractor
from ccs.core.protocols import ProtocolManager

# Initialize components
embedder = CCSEmbedder(config)
extractor = CCSExtractor(config)
protocol_manager = ProtocolManager()

# Select a protocol
protocol = protocol_manager.get_protocol("P042")  # Content-hash based

# Prepare stego-key
stego_key = {
    'protocol': protocol,
    'encryption_key': b'32-byte-encryption-key-here',
    'credentials': {'api_key': 'your-api-key'}
}

# Embed secret message
secret = "Classified information"
cover_folders = ["/path/to/cover/folder1", "/path/to/cover/folder2"]
stego_folder = embedder.embed(secret, cover_folders, stego_key)

# Extract secret message
extracted = extractor.extract(stego_folder, cover_folders, stego_key)
print(f"Extracted: {extracted}")  # Should match original
```

### Concrete Example (Section 4.3 from Paper)
```bash
# Run the complete example from the paper
cd examples
python concrete_example.py
```

### Enterprise Deployment
```bash
# Run enterprise deployment example
cd examples
python enterprise_deployment.py
```

## 📁 Project Structure

```
ccs-framework/
├── src/                    # Source code
│   ├── core/              # Core algorithms (embedding, extraction)
│   ├── cloud/             # Cloud provider integrations
│   └── utils/             # Utilities (error handling, monitoring)
├── config/                # Configuration files
├── tests/                 # Comprehensive test suite
├── examples/              # Usage examples
```

## 🧪 Testing

Run the complete test suite to verify installation:

```bash
# Run all tests
make test

# Run performance benchmarks
make test-performance

# Run security tests
make test-security

# Run robustness tests
make test-robustness
```

### Test Results Verification
The test suite validates:
- **Capacity scaling** (logarithmic growth with folder size)
- **Security properties** (indistinguishability from normal folders)
- **Performance metrics** (sub-second processing for 1024 files)
- **Robustness** (93-98% success in dynamic environments)

## 🔐 Security Considerations

### Threat Model
CCS is designed to resist:
- **Passive statistical analysis** (p > 0.75 in all tests)
- **Active modification attacks** (cryptographic integrity checks)
- **Protocol discovery attacks** (480+ protocol combinations)
- **Insider threats** (multiple security layers)

### Security Best Practices
1. **Use content-based protocols** for maximum stability
2. **Rotate protocols regularly** to minimize long-term risk
3. **Implement access controls** for steganography folders
4. **Monitor for anomalous patterns** in cloud usage
5. **Use strong encryption keys** (32+ bytes)

## 📈 Performance

### Capacity Scaling
| Folder Size | CCS Capacity | Base-8 | Improvement |
|-------------|--------------|--------|-------------|
| 64 files | 6 bits | 3 bits | 2.0× |
| 256 files | 8 bits | 3 bits | 2.7× |
| 1024 files | 10 bits | 3 bits | 3.3× |
| 4096 files | 12 bits | 3 bits | 4.0× |

### Processing Times (Average)
| Operation | 256 files | 1024 files | 4096 files |
|-----------|-----------|------------|------------|
| Embedding | 0.68s | 2.05s | 8.45s |
| Extraction | 0.52s | 1.63s | 6.74s |
| Total | 1.20s | 3.68s | 15.19s |

## 🌐 Cloud Provider Support

CCS supports multiple cloud storage providers:

| Provider | API | Authentication | Rate Limits |
|----------|-----|---------------|-------------|
| **Google Drive** | v3 | OAuth 2.0 | 1,000 requests/day |
| **Dropbox** | v2 | OAuth 2.0 | 1,200 requests/hour |
| **OneDrive** | Graph API | Azure AD | 10,000 requests/10 min |

### Configuration Example
```yaml
# config/cloud_config.yaml
google_drive:
  client_id: "your-client-id"
  client_secret: "your-client-secret"
  redirect_uri: "http://localhost:8080/callback"

dropbox:
  app_key: "your-app-key"
  app_secret: "your-app-secret"

onedrive:
  tenant_id: "your-tenant-id"
  client_id: "your-client-id"
```

## 🔬 Research Validation

### Experimental Results (30-day study)
- **Capacity**: 3.2× to 4.3× improvement over base-B methods
- **Security**: All statistical tests passed (p > 0.75)
- **Robustness**: 95.2-97.8% extraction success in dynamic environments
- **Performance**: Sub-second processing for realistic folder sizes

### Comparison with State-of-the-Art
| Method | Capacity | Security | Undetectability |
|--------|----------|----------|-----------------|
| Base-B Encoding | Low | Medium | High |
| Multi-Cloud | Medium | High | High |
| **CCS (Proposed)** | **High** | **High** | **High** |


### Key Algorithms Implemented
1. **Algorithm 1**: CCS Embedding with AES encryption
2. **Algorithm 2-3**: Optimized extraction with HMAC verification
3. **Algorithm 4-5**: Concrete example from Section 4.3
4. **Algorithm 7**: Proactive change detection
5. **Algorithm 8**: Enterprise-grade fault tolerance

## 🚀 Deployment

### Development Environment
```bash
# Set up development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

### Production Deployment
```bash
# Build package
make build

# Deploy to production
make deploy-prod
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "examples/enterprise_deployment.py"]
```

## 📊 Benchmarking

Run comprehensive benchmarks:
```bash
# Generate performance report
cd tests/performance
python benchmark.py

# Results saved to performance_report.json
```

Expected results (for 1024 files):
- Embedding time: 2.05 ± 0.35s
- Extraction time: 1.63 ± 0.26s
- Capacity: 10 bits per folder
- Success rate: >97%

