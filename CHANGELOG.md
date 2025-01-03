# Changelog
All notable changes to M-MAP will be documented in this file.

## [1.6.0] - 2025-01-04

### ✨ New Features
- Added service detection with banner grabbing
- Added type hints for better code quality
- Added new validation functions:
  - `validate_ip()` for IP address validation
  - `validate_subnet()` for subnet validation
  - `parse_port_range()` for port range parsing
- Added docstrings for better documentation
- Added new service name resolution function
- Added host resolution function

### 🐛 Bug Fixes
- Fixed invalid escape sequence in ASCII banner
- Fixed socket timeout issues in UDP scanning
- Fixed banner encoding issues in service detection
- Fixed thread management in multi-port scanning
- Fixed progress bar calculation

### 🔨 Improvements
- Increased test coverage from 30% to 48%
- Added new unit tests:
  - Network scanning tests
  - Service detection tests
  - Port range parsing tests
  - IP validation tests
- Improved code organization
- Enhanced service detection accuracy
- Better error handling and user feedback
- Optimized thread management
- Improved progress reporting

### 🔒 Security
- Added input validation for all user inputs
- Improved error handling for network operations
- Added timeout controls for all network operations

### 📚 Documentation
- Added detailed docstrings
- Improved help messages
- Added type hints
- Updated README.md

## [1.5.0] - 2021-08-21

### Features
- Initial release
- Basic port scanning
- Multi-threading support
- Quick scan option
- Export functionality 