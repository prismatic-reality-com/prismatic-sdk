# Changelog

All notable changes to the Prismatic SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial SDK implementation with comprehensive API coverage
- Authentication support (API keys, JWT tokens, Basic auth)
- Complete Perimeter (EASM) service integration
- Full OSINT service with 120+ sources
- Sandboxed Labs service for secure code execution
- Real-time WebSocket support for monitoring
- Built-in rate limiting with intelligent retry logic
- Circuit breaker protection for fault tolerance
- Comprehensive telemetry and metrics
- Extensive test suite with property-based testing
- Rich documentation with real-world examples

### Security
- Secure credential handling with multiple auth methods
- Rate limiting to prevent API abuse
- Circuit breaker protection against service failures
- Input validation and sanitization
- Secure WebSocket connections with authentication

## [0.1.0] - 2026-02-21

### Added
- Initial release of the Prismatic SDK for Elixir
- Core HTTP client with authentication
- Perimeter (EASM) service wrapper
- OSINT intelligence service wrapper
- Labs sandboxed execution service wrapper
- WebSocket support for real-time updates
- Rate limiting and circuit breaker infrastructure
- Telemetry and monitoring capabilities
- Test helpers and comprehensive test suite
- Complete API documentation

### Features

#### Authentication
- API key authentication for service-to-service communication
- JWT bearer token support for user authentication
- Basic authentication for legacy systems
- Automatic token refresh with retry logic
- Permission checking and user info retrieval

#### Perimeter (EASM) Service
- External attack surface discovery for domains
- A-F security ratings with industry benchmarking
- Certificate discovery via CT logs
- Continuous monitoring with alerting
- Risk assessment with evidence aggregation
- NIS2 and Czech ZKB compliance assessment
- Threat intelligence integration
- Multi-tenant support with workspace isolation
- Dashboard metrics and reporting

#### OSINT Intelligence Service
- Comprehensive investigations across 120+ sources
- Czech-specific sources (ARES, Justice, ISIR)
- Global sources (Shodan, VirusTotal, Hunter.io)
- Sanctions list checking (EU, OFAC, UN)
- Source health monitoring and management
- Investigation progress tracking
- Findings categorization and risk scoring
- Target validation and type detection

#### Labs Service
- Multiple lab types (Playbook, Blackboard, Lean4, Smalltalk)
- Secure sandbox isolation with resource limits
- Session lifecycle management
- Code execution with comprehensive monitoring
- Classification levels for security control
- Resource quota management by user/role
- Execution history and audit trails
- Real-time resource usage monitoring

#### Infrastructure
- HTTP client with Finch connection pooling
- Intelligent rate limiting with token bucket algorithm
- Circuit breaker protection with configurable thresholds
- WebSocket support with automatic reconnection
- Comprehensive telemetry with Telemetry.Metrics
- Health checking across all components
- Graceful error handling and retry logic
- Configuration management with runtime support

#### Developer Experience
- Rich documentation with HexDocs
- Comprehensive test suite with >90% coverage
- Test helpers for easy mocking and testing
- Real-world usage examples
- Property-based testing with StreamData
- Detailed error messages and debugging
- TypeScript-style typespecs throughout

### Technical Details

#### Dependencies
- Req ~> 0.4.0 for HTTP client functionality
- WebSockex ~> 0.4.0 for WebSocket support
- Jason ~> 1.4 for JSON handling
- JOSE ~> 1.11 for JWT token processing
- ExRated ~> 2.0 for rate limiting
- Fuse ~> 2.4 for circuit breaker functionality
- Telemetry ~> 1.2 for metrics and monitoring

#### Architecture
- OTP application with proper supervision tree
- GenServer-based components for stateful services
- Registry-based process management
- ETS tables for high-performance caching
- Dynamic supervisors for connection management
- Behaviour-driven design with clear contracts

#### Performance
- Connection pooling with configurable pool sizes
- Automatic request retries with exponential backoff
- Intelligent rate limiting to maximize throughput
- Circuit breakers to prevent cascade failures
- Efficient WebSocket message handling
- Minimal memory footprint with garbage collection

#### Security
- Secure credential storage and transmission
- Input validation and sanitization
- Rate limiting to prevent abuse
- Authentication and authorization checks
- Secure WebSocket connections
- Audit logging for security events

### Breaking Changes
- None (initial release)

### Deprecated
- None (initial release)

### Removed
- None (initial release)

### Fixed
- None (initial release)

---

## Release Process

1. Update version in `mix.exs`
2. Update `CHANGELOG.md` with new version
3. Run full test suite: `mix test`
4. Build documentation: `mix docs`
5. Create git tag: `git tag v0.1.0`
6. Push to repository: `git push origin v0.1.0`
7. Publish to Hex: `mix hex.publish`
8. Update documentation: `mix docs`

## Migration Guides

### Upgrading from 0.x to 1.0 (Future)
- TBD when 1.0 is released

---

For more information about releases, see the [GitHub Releases page](https://github.com/prismatic-platform/prismatic-sdk-elixir/releases).