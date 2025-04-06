# Zero-Knowledge Proof-Based Client-Server Authentication System

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Project Information
- **Author**: Omar Ahmed Badrawy 
- **Version**: 1.0.0

## Overview
A secure authentication system implementing Zero-Knowledge Proofs (ZKPs) for user authentication without revealing sensitive information. The system uses a client-server architecture with Python-based implementation.

### Technical Details
- **ZKP Protocol**: Schnorr protocol implementation
- **Cryptographic Parameters**:
  - Prime modulus (P): 3557
  - Generator (g): 3
  - Generator (h): 5
- **Encryption**: AES-128 in CFB mode
- **Communication**: TCP socket-based (port 9998)

## Features
- Secure user authentication using Zero-Knowledge Proofs
- Client-server architecture with socket-based communication
- Local data encryption using AES-128
- Performance metrics collection and monitoring
- Thread-safe server implementation
- JSON-based data persistence
- Rate limiting and input validation
- Comprehensive error handling

## System Architecture
```
├── client/
│   ├── client.py           # Client implementation
│   ├── client_secrets.json # Encrypted user data
│   └── client_metrics.json # Performance metrics
└── server/
    ├── server.py           # Server implementation
    ├── server_data.json    # User records
    └── server_metrics.json # Server metrics
```

## Prerequisites
- Python 3.x
- Required Python packages:
  - pycryptodome
  - psutil
  - json
  - socket
  - threading
  - logging

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/zkp-auth-system.git
cd zkp-auth-system
```

2. Install dependencies:
```bash
pip install pycryptodome psutil
```

## Usage
1. Start the server:
```bash
python server/server.py
```

2. Run the client:
```bash
python client/client.py
```

3. Follow the on-screen instructions to:
   - Sign up with a new account
   - Log in with existing credentials

### Example Usage
```python
# Client-side authentication flow
username = "test_user"
password = 12345  # For demo purposes, using integers
sign_up(username, password)
login(username, password)
```

## Security Features
- Zero-Knowledge Proof implementation for password verification
- AES-128 encryption for local data storage
- Thread-safe server operations
- Input validation and error handling
- Rate limiting for sign-up attempts
- Secure socket communication
- Data persistence with encryption

## Performance Metrics
The system collects and logs:
- CPU and memory usage
- Network latency
- Processing time for operations
- Authentication success rates
- Thread performance metrics

### Example Metrics Output
```json
{
    "operation": "LOGIN",
    "processing_time": 0.001,
    "cpu_usage": 2.5,
    "memory_usage": 32.5
}
```

## Troubleshooting
1. **Server Connection Issues**
   - Check if port 9998 is available
   - Verify firewall settings
   - Ensure server is running

2. **Authentication Failures**
   - Verify username/password format
   - Check network connectivity
   - Review server logs for errors

3. **Performance Issues**
   - Monitor system resources
   - Check for concurrent connections
   - Review metrics logs

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

### Development Guidelines
1. Follow PEP 8 style guide
2. Add tests for new features
3. Update documentation
4. Maintain backward compatibility

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- Dr. Muhammad Hataba for guidance
- John Ehab for technical support
- The Cryptography course at GIU for the opportunity to develop this project

## References
- [Zero-Knowledge Proofs Overview](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
- [Schnorr Protocol Documentation](https://en.wikipedia.org/wiki/Schnorr_signature)
- [Python Cryptography Documentation](https://cryptography.io/en/latest/) 