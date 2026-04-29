# Changelog

All notable changes to this project will be documented in this file.

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