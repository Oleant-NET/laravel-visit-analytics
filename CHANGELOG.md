# Changelog

All notable changes to this project will be documented in this file.

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