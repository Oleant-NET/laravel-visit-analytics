# Changelog

All notable changes to this project will be documented in this file.

## [2.6.1] — 2026-07-19
### Fixed
- **Configuration:** Resolved an issue where analysis rules were not being correctly passed from the configuration to the analyzers. This ensures that custom thresholds and behavior weights are now properly applied during bot analysis.

## [2.6.0] — 2026-07-17
### Added
- **Behavioral Analysis:** Implemented `suspicious_entry` detection in `BehaviorAnalyzer`. The system now identifies and flags (with a configurable weight) bots that initiate sessions on internal pages by spoofing an internal referer without having a corresponding entry point in the session history.

- **Configurability:** Added `suspicious_entry weight` to the configuration file, allowing users to define the severity (`default: 100`) for bots attempting to simulate navigation paths

## [2.5.2] — 2026-06-07
### Fixed
- **Model Integrity:** Implemented `setUrlAttribute` mutator in `VisitLog` model to prevent `SQLSTATE[22001]: String data, right truncated` errors caused by excessively long URLs from malicious bot scans.
- **Data Safety:** Added unit tests to ensure URL truncation logic correctly handles strings exceeding 255 characters.

## [2.5.1] — 2026-06-02
### Fixed
- **Behavior Analysis:** Fixed false-positive header_set_anomaly flags.

- **Logic:** Improved checkHeaderSetStability to distinguish between "identity rotation" (bot behavior) and "natural session growth" (loading `AJAX`, `cookies`, or `XHR`).

- **Stability:** The analyzer now allows header sets to expand over time without triggering a penalty. Penalties are now strictly applied only when core browser identifiers are lost or removed during a session.

- **Testing:** Updated BehaviorAnalyzerTest to reflect real-world browser behavior (successful passing of sequential requests with extra headers).

### Added
- **Configuration:** Introduced dynamic_headers parameter in `config/visit-analytics.php` to define transient HTTP headers that fluctuate based on request context (e.g., `sec-fetch-dest`, `x-requested-with`). This allows for granular control over which headers should be ignored during stability checks.

## [2.5.0] - 2026-06-01
### Added
- **Header Stability Analysis:** Introduced checkHeaderSetStability to the BehaviorAnalyzer. This new detection mechanism identifies "lazy" bots that rotate request fingerprints (header sets) during a session, significantly improving bot detection precision without additional database overhead.

- **New configuration parameter:** Added header_set_anomaly weight to the configuration file, allowing fine-grained control over the detection sensitivity.

- **Extended Test Suite:** Added feature tests for HeaderSetStability to ensure reliable detection of fingerprint inconsistencies.

### Changed
Internal logic: Enhanced the behavioral analysis flow to catch sophisticated bot patterns that mimic legitimate browser behavior while failing to maintain a consistent fingerprint.

## [2.4.0] - 2026-05-25

### Breaking Changes
- **Database Schema:** Removed `botnet_fingerprints` table.
- **Migration Required:** - Run `Schema::dropIfExists('botnet_fingerprints');` to clean up the obsolete storage.
  - Add `fingerprint_hash` index to `visit_logs` for real-time lookups:
    ```php
    Schema::table('visit_logs', function (Blueprint $table) {
        $table->string('fingerprint_hash', 64)->nullable()->index()->after('id');
    });
    ```
- **Configuration:** Added `anonymization` block to `config/visit-analytics.php`. Ensure you publish the new config:
  `php artisan vendor:publish --tag=visit-analytics-config`

### Added
- **`FingerprintAnonymizerService`:** Real-time data sanitization (UA stripping, header key-only mode).
- **`BotnetAnalyzer`:** Real-time cluster detection based on high-frequency fingerprint occurrences across distinct IPs.
- **Middleware `TrackVisits`:** Now generates and persists unique `fingerprint_hash` for smarter bot tracking.

### Changed
- **Core Detection Logic:** Switched from static User-Agent matching to multi-factor "digital skeleton" analysis (UA + Client Hints).
- **Architecture:** Transitioned from historical database lookups to an "in-memory" (within current time window) analysis strategy.

### Privacy-First
- Logs are now transformed into non-identifiable statistical aggregates, ensuring compliance by design.

## [2.3.0] - 2026-05-22

### Added

- **Deferred Anonymization Pipeline**: Implemented a non-blocking, deferred anonymization system for visit logs. Sensitive IP addresses are now masked automatically after a configurable retention period (defined via `anonymization.retention_minutes`), ensuring GDPR compliance while maintaining data availability for real-time analysis.

- **Enhanced Referer Analysis**: Updated `RefererAnalyzer` to support `Sec-Fetch-Site` metadata. The system now correctly distinguishes between suspicious self-referencing loops and legitimate internal navigation (AJAX, anchor links, same-origin transitions), significantly reducing false positives.

- **RetroAnalysis Safety Layer**: Added automated validation in `RetroAnalysisService` to prevent "lookback" windows from exceeding the configured data retention period. Added warning logging for misconfigurations.

### Changed

- **Database Schema**: 
    - Added `anonymized_at` column to the `visit_logs` table.
    - Added an index to `anonymized_at` for high-performance retrieval during deferred processing.

- **Service Architecture**: Refactored `IpAnonymizerService` to support secure IPv4/IPv6 masking with improved regex validation and clear documentation.

- **Optimization**: Optimized `runDeferredAnonymization` using chunked processing to maintain memory efficiency during batch updates.

### Fixed

- **Data Integrity**: Added `whereNull('anonymized_at')` to all retro-analysis queries to ensure that sensitive data processing does not overlap with anonymization tasks.

- **Referer Logic**: Resolved issues where legitimate site interactions were incorrectly flagged as `referer_loop` by implementing strict host-path validation using `parse_url` and contextual header checks.

- **Testing**: Updated test suite to account for the new deferred anonymization lifecycle and updated `RefererAnalyzer` logic to ensure coverage for both legitimate same-origin requests and malicious loops.

---

### Upgrade Guide

> [!IMPORTANT]
> **Database Migration**: Run `php artisan migrate` to apply the schema changes (adding `anonymized_at` column and index).

- **Configuration**: Ensure `anonymization.retention_minutes` is defined in your `visit-analytics.php` config file.
- **Reporting Warning**: Please be aware that enabling the anonymization pipeline will mask IP addresses in historical logs after the specified retention period. Ensure your reporting tools are adjusted accordingly to avoid data discrepancies.

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
