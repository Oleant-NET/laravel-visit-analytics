# Changelog

All notable changes to this project will be documented in this file.

## [2.2.0] - 2026-05-15

### Added
- **Botnet Reputation System**: New `BotnetReputationAnalyzer` layer that checks visitors against a local database of known botnet fingerprints.
- **Cluster Detection Logic**: Implemented `BotnetService` capable of identifying coordinated attacks (clusters) where multiple IPs use identical signatures.
- **New Database Layer**: Added `botnet_fingerprints` table to store and track identified botnet signatures.
- **Automated Fingerprinting**: The `analyze-bots` command now automatically identifies and saves new botnets if they meet the threshold (e.g., 50+ visits from 10+ unique IPs).

### Changed
- **Extended Analyzer Chain**: Increased total analysis layers to 12.
- **Improved Evidence Tracking**: Refactored `AnalysisState` to support `addEvidence()` for better semantic reporting of bot signatures.

### Testing
- **New Test Suites**: Added comprehensive tests for `BotnetService`, `BotnetReputationAnalyzer`, and extended `AnalyzeBots` command coverage.
- **Reliability**: Verified protection against duplicate fingerprinting and IP anonymization edge cases.

## [2.1.0] - 2026-05-13

### Added
Added anonymize_bots configuration option to allow preserving full IP addresses for detected bots (useful for security analysis and blacklisting).

### Added .env support for all privacy settings:

**VISIT_ANALYTICS_ANONYMIZE_IP**

**VISIT_ANALYTICS_ANONYMIZE_MODE**

**VISIT_ANALYTICS_ANONYMIZE_BOTS**

### Changed
**Major Refactoring:** Centralized all anonymization logic within IpAnonymizerService.

**Refactored TrackVisits** middleware to delegate all IP processing to the service, improving maintainability.

**Updated AnalyzeBots** console command to support the new final processing stage, ensuring IPs are masked only after bot analysis is complete in async mode.

**Updated configuration file** with detailed documentation regarding GDPR/DSGVO compliance for each mode.

### Fixed
- Fixed `IpAnonymizerService` test suite to correctly run within the Laravel `TestCase` environment.
- Improved handling of invalid IP strings and IPv4-mapped IPv6 addresses.

### Testing
- Expanded test suite to **100+ tests** with over **200 assertions**, covering all anonymization scenarios, bot detection logic, and configuration edge cases.


## [2.0.1] - 2026-05-10

### Fixed: Missing millisecond precision in VisitLog timestamps.

### Added: Model $dateFormat support and precision integrity tests.


## [2.0.0] - 2026-05-09

### Added
- **Plugin-based Analyzer Architecture**: Decoupled detection logic into 11 specific classes (UserAgent, Network, Behavior, HeaderIntegrity, etc.).
- **AnalysisState Object**: New state carrier to track scores, reasons, and technical evidence across the chain.
- **Millisecond Precision Support**: Updated migrations to use `timestamp(3)` for `created_at` in `visit_logs` table, enabling high-precision behavior analysis and detection of ultra-fast automated requests.
- **New Detection Layers**: Added HeaderIntegrity, ObsoleteOS, OutdatedBrowser, and Honeypot analyzers.
- **Comprehensive Test Suite**: Massive update with 86 tests and 204 assertions providing 100% coverage.

### Changed
- **Architectural Refactor**: Full transition from a monolithic command to a service-oriented system with 2 core services and 11 analyzers.
- **Config Modularization**: Weights and thresholds are now logically grouped by analyzer type (UA, Network, Behavior).
- **Scoring Precision**: Refined detection algorithms to significantly reduce false positives by implementing cumulative scoring and context-aware checks.
- **Database Schema**: Enhanced `visit_logs` table structure to support high-resolution timing and better indexing for historical lookups.

### Fixed
- **DNS Handling**: Improved exception handling for slow or timed-out DNS/PTR lookups to prevent analysis bottlenecks.
- **AJAX False Positives**: Behavior analyzer now correctly identifies and ignores modern SPA/Vue/React background requests when calculating navigation speed.

### Removed (Breaking Changes)
- **Legacy Config**: Old configuration structure is no longer supported. Users must republish the config file using `php artisan vendor:publish --tag="visit-analytics-config" --force`.
- **Monolithic Analyzer**: Removed the old single-class analysis logic in favor of the new plugin system.

## Upgrade Guide: From 1.x to 2.0.0

Version 2.0.0 introduces a complete architectural rewrite, moving from a monolithic command to a service-oriented system with 11 specialized analyzers. This release improves detection precision and performance but requires manual update steps.

### 1. Update Composer Dependency
Update your version constraint in `composer.json` to `^2.0` and run:
```bash
composer update oleant/laravel-visit-analytics
```

### 2. Database Schema Update (High Precision Timestamps)
The database schema has been enhanced to support high-resolution timing. You must run the migrations to update the `visit_logs` table to use `timestamp(3)` for the `created_at` column.
```bash
php artisan migrate
```

### 3. Replace Configuration File
The configuration structure has been modularized and grouped by analyzer type. Your old `visit-analytics.php` config is not compatible with v2.0.

1. Backup your old weights if you customized them.
2. Force-republish the new config:
```bash
php artisan vendor:publish --tag="visit-analytics-config" --force
```
3. Re-apply your custom weights using the new logical sections.

### 4. Clear Cache
After updating the migrations and configuration, clear your application cache:
```bash
php artisan config:clear
php artisan cache:clear
```

## [1.3.0] - 2026-05-02

### Added
- **Snowball Effect (Retroactive Cleanup)**: Introduced a mechanism that automatically flags historical sessions of a newly identified bot IP. All previous "clean" records within a 60-day window are updated to bot status.
- **Technical Port Leak Detection**: New detection layer for suspicious technical ports (e.g., :2082, :8443) in the Referer header, effectively catching hosting control panel scanners.
- **Retroactive Metrics**: Real-time "Retroactive Hits" counter in the console output during analysis.
- **Comprehensive Test Suite**: 100% coverage of new features with PEST, including 32 assertions for retroactive logic and port detection.

### Changed
- **Configurable Port Detection**: Technical ports and their respective weights are now managed via the `port_leak` and `weights.port_leak` configuration keys.
- **Modular Scoring**: Improved separation between Static and Behavioral analysis for better precision.
- **Performance Optimization**: Implemented composite indexing for high-speed historical lookups.

### Fixed
- **Schema Consistency**: Finalized database schema and indexes to ensure seamless updates from previous versions.

## [1.2.0] - 2026-04-29

### Added
- **Referer Loop Detection**: New logic to detect bots faking referer headers (URL == Referer) on first-time visits.
- **F5 Refresh Awareness**: Added history verification to allow legitimate page refreshes for real users.
- **Advanced UA Checks**: Implemented regex patterns with version-specific bonuses (e.g., Chrome future versions).

### Changed
- **Modular Scoring Architecture**: Refactored analysis into static, behavioral, and network stages for better maintainability.
- **Referer Normalization**: URL and Referer are now normalized (stripping protocols and trailing slashes) before comparison.

### Fixed
- Improved accuracy of behavioral analysis by fixing IP/URL history lookups.

## [1.1.0] - 2026-04-26

### Added
- **Deep Bot Analysis**: New `visit-analytics:analyze-bots` command for background traffic profiling.
- **Scoring System**: Implemented behavioral and network scoring (0-100).
- **Database Schema**: Added `bot_score`, `is_bot`, and `processed_at` fields to `visit_logs` table.
- **Indexes**: Added performance indexes for faster log analysis.
- **Scheduling Support**: Documentation for automated bot detection.

### Changed
- Improved IP detection logic for Cloudflare environments.
- Updated default configuration with behavioral analysis thresholds.

### Fixed
- Potential memory leak when processing large volumes of logs.