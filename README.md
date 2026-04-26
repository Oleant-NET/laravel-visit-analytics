# Laravel Visit Analytics

Lightweight, privacy-focused visit analytics for Laravel 10, 11, and 12. Track UTM parameters, referrers, and page views while automatically filtering out bots and respecting user privacy.

## Features
- **Smart Bot Detection**: Uses behavioral and network analysis beyond simple User-Agent checks.
- **Bot Scoring System**: Assigns a score based on access speed, DNS records, and honeypot hits.
- **Retroactive Flagging**: Identifies previous visits from an IP once it's confirmed as a bot.
- **Privacy First**: IP anonymization (masks the last octet) enabled by default.
- **Cloudflare Ready**: Automatically detects real visitor IP via `CF-Connecting-IP` header.
- **Zero Latency**: Logging happens in the `terminate` middleware *after* the response is sent to the user.
- **Flexible Exclusions**: Easily ignore specific IPs, paths (like `/admin*`), or bots.

## Installation

Run this command in your terminal:
```bash
composer require oleant/laravel-visit-analytics
```

## Database Setup

Create or update the necessary table by running migrations:

```bash
php artisan migrate
```

## Configuration

Publish the config file to customize tracking rules, weights, and thresholds:

```bash
php artisan vendor:publish --tag="visit-analytics-config"
```

### Key Config Options:
* `anonymize_ip`: (bool) Mask the last digit of IPv4 addresses.
* `exclude.ips`: (array) List of IP addresses to ignore.
* `exclude.paths`: (array) URL patterns to skip (e.g., `['admin*', 'api/*']`).
* `track_bots`: (bool) Whether to log search engine crawlers.
* `behavioral_analysis.threshold`: (int) Score (0-100) at which a visitor is flagged as a bot.
* `whitelist`: (array) Only these GET parameters will be saved in the `payload`.

## Usage

### Middleware Registration
For Laravel 11 & 12, open `bootstrap/app.php`:
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \Oleant\VisitAnalytics\Http\Middleware\TrackVisits::class,
    ]);
})
```

### Bot Analysis Command
To perform deep analysis (checks DNS, speed, and patterns), run the command:

```bash
# Analyze last 1000 records
php artisan visit-analytics:analyze-bots --max=1000 --full
```

It is recommended to schedule this in `routes/console.php`:
```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('visit-analytics:analyze-bots --max=500')->everyTenMinutes();
```

## Cloudflare Setup & Security

### Real IP Detection
The package automatically prioritizes the `CF-Connecting-IP` header. No extra configuration is needed to see real visitor IPs.

### Avoid Self-Banning (WAF Rules)
If you are using Cloudflare WAF, ensure your server's IP is added to the **IP Access Rules** in the Cloudflare Dashboard:
1. Go to **Security > WAF > Tools**.
2. Add your **Server IP** to the whitelist with the action **"Allow"**.

## Data Retrieval

To get your stats, just use the Eloquent model:

```php
use Oleant\VisitAnalytics\Models\VisitLog;

// Get latest human visits
$visits = VisitLog::where('is_bot', false)->latest()->paginate(50);

// Get identified bots
$bots = VisitLog::where('is_bot', true)->latest()->get();
```

## License
The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.

Built with ❤️ for [Oleant Auditor](https://oleant.net).