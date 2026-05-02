# Changelog

All notable changes to this project will be documented in this file.

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