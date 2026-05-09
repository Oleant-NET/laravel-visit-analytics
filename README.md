# Laravel Visit Analytics

Lightweight, privacy-focused visit analytics for Laravel 10, 11, and 12. Track UTM parameters, referrers, and page views while automatically filtering out bots and respecting user privacy.

## Features
- **Modular Analyzer Engine**: 11 specialized layers including Behavioral, Network, and Header integrity analysis.
- **Smart Bot Detection**: Advanced behavioral analysis including Referer-loop detection and page-refresh awareness.
- **Bot Scoring System**: Assigns a score based on access speed, DNS records, and honeypot hits.
- **Retroactive Flagging**: Identifies previous visits from an IP once it's confirmed as a bot (Snowball Effect).
- **Privacy First**: IP anonymization (masks the last octet) enabled by default.
- **Cloudflare Ready**: Automatically detects real visitor IP via `CF-Connecting-IP` header.
- **Zero Latency**: Logging happens in the `terminate` middleware *after* the response is sent to the user.

## Installation

Run this command in your terminal (BASH):
```bash
composer require oleant/laravel-visit-analytics
```

## Database Setup

Create or update the necessary table by running migrations (BASH):

> **Important:** Version 2.0+ introduces high-precision timing. The `created_at` column now uses **millisecond precision** (`timestamp(3)`). This is critical for the Behavioral Analyzer to accurately detect ultra-fast automated requests and scripts.

```bash
php artisan migrate
```

## Configuration

> **Note for Upgraders (v1.x to v2.0):** This version introduces a completely new configuration schema. You must backup your old settings and republish the config file.

Run command (BASH):
```bash
php artisan vendor:publish --tag="visit-analytics-config" --force
```

### Key Config Options:
The configuration is now organized by specialized Analyzers:
* analyzers.behavior: Configure request frequency and timing thresholds.
* analyzers.ua: Rules for User-Agent parsing and Client-Hints validation.
* analyzers.network: Settings for DNSBL, PTR records, and IP reputation.
* analyzers.headers: Checks for missing or inconsistent browser headers.
* exclude.ips: List of IP addresses to ignore.
* exclude.paths: URL patterns to skip (e.g., ['admin*', 'api/*']).

## Usage

### Middleware Registration
For Laravel 11 & 12, open bootstrap/app.php (PHP):
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \Oleant\VisitAnalytics\Http\Middleware\TrackVisits::class,
    ]);
})
```

### Bot Analysis Command
To perform deep analysis using the new multi-stage engine (BASH):

```bash
# Analyze last 1000 records
php artisan visit-analytics:analyze-bots --max=1000
```

It is recommended to schedule this in routes/console.php (PHP):
```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('visit-analytics:analyze-bots --max=500')->everyTenMinutes();
```

## Cloudflare Setup & Security

### Real IP Detection
The package automatically prioritizes the CF-Connecting-IP header. No extra configuration is needed to see real visitor IPs.

### Avoid Self-Banning (WAF Rules)
If you are using Cloudflare WAF, ensure your server's IP is added to the IP Access Rules in the Cloudflare Dashboard to prevent the analysis command from being blocked during DNS/Network checks.

## Data Retrieval

To get your stats, just use the Eloquent model (PHP):

```php
use Oleant\VisitAnalytics\Models\VisitLog;

// Get latest human visits
$visits = VisitLog::where('is_bot', false)->latest()->paginate(50);

// Get identified bots
$bots = VisitLog::where('is_bot', true)->latest()->get();
```

## License
The MIT License (MIT). Please see LICENSE.md for more information.

Built with ❤️ for [Oleant Auditor](https://oleant.net).