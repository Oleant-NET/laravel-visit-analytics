# Laravel Visit Analytics

Lightweight, privacy-focused visit analytics for Laravel 10, 11, and 12. Track UTM parameters, referrers, and page views while automatically filtering out bots and respecting user privacy.

## Features
- **Bot Detection**: Automatically skips crawlers using `jaybizzle/crawler-detect`.
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

Create the necessary table by running migrations:

```bash
php artisan migrate
```

## Configuration

Publish the config file to customize tracking rules (anonymization, whitelists, exclusions):

```bash
php artisan vendor:publish --tag="visit-analytics-config"
```

### Key Config Options:
* `anonymize_ip`: (bool) Mask the last digit of IPv4 addresses.
* `exclude.ips`: (array) List of IP addresses to ignore.
* `exclude.paths`: (array) URL patterns to skip (e.g., `['admin*', 'api/*']`).
* `track_bots`: (bool) Whether to log search engine crawlers and bots.
* `whitelist`: (array) Only these GET parameters will be saved in the `payload` (e.g., `['utm_source', 'utm_medium']`).

## Usage

### For Laravel 11 & 12
Open `bootstrap/app.php` and register the middleware:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: [
        \Oleant\VisitAnalytics\Http\Middleware\TrackVisits::class,
    ]);
})
```

### For Laravel 10
Open `app/Http/Kernel.php` and add the class to the `$middlewareGroups` array under `web`:

```php
protected $middlewareGroups = [
    'web' => [
        // ...
        \Oleant\VisitAnalytics\Http\Middleware\TrackVisits::class,
    ],
];
```

## Cloudflare Setup & Security

### Real IP Detection
The package automatically prioritizes the `CF-Connecting-IP` header. No extra configuration is needed to see real visitor IPs.

### Avoid Self-Banning (WAF Rules)
If you are using Cloudflare WAF or Rate Limiting, ensure your server's IP is added to the **IP Access Rules** in the Cloudflare Dashboard:
1. Go to **Security > WAF > Tools**.
2. Add your **Server IP** to the whitelist with the action **"Allow"**.
3. This prevents Cloudflare from triggering security challenges when your server communicates with its own services or when you perform maintenance.

## Data Retrieval

To get your stats, just use the Eloquent model:

```php
use Oleant\VisitAnalytics\Models\VisitLog;

// Get latest visits
$visits = VisitLog::latest()->paginate(50);
```

## License
The MIT License (MIT). Please see [LICENSE.md](LICENSE.md) for more information.

Built with ❤️ for [Oleant Auditor](https://oleant.net).