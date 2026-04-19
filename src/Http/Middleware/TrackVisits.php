<?php

namespace Oleant\VisitAnalytics\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Oleant\VisitAnalytics\Models\VisitLog;
use Symfony\Component\HttpFoundation\Response;
use Jaybizzle\CrawlerDetect\CrawlerDetect;
use Illuminate\Support\Str;

class TrackVisits
{
    /**
     * Handle tasks after the response has been sent to the browser.
     */
    public function terminate(Request $request, Response $response): void
    {
        $excludePaths = config('visit-analytics.exclude.paths', []);
        
        // Extract referer path to catch background requests from excluded areas
        $referer = $request->headers->get('referer');
        $refererPath = $referer ? parse_url($referer, PHP_URL_PATH) : null;
        $refererPath = $refererPath ? ltrim($refererPath, '/') : null;

        // 1. Path & Referer Filtering
        foreach ($excludePaths as $path) {
            // Check if current URL matches exclusion pattern
            if ($request->is($path)) {
                return;
            }

            // Check if request originated from an excluded path (e.g. Livewire update from Admin)
            if ($refererPath && Str::is($path, $refererPath)) {
                return;
            }
        }

        // 2. IP Exclusion
        if (in_array($request->ip(), config('visit-analytics.exclude.ips', []))) {
            return;
        }

        // 3. Auth Filter (Ignore logged-in users if configured)
        if (config('visit-analytics.exclude.ignore_authenticated', false) && auth()->check()) {
            return;
        }

        // 4. Bot Detection
        if (!config('visit-analytics.track_bots', false)) {
            $crawlerDetect = new CrawlerDetect;
            if ($crawlerDetect->isCrawler($request->userAgent())) {
                return;
            }
        }

        $this->logVisit($request);
    }

    /**
     * Extract and log the visitor's data to the database.
     */
    protected function logVisit(Request $request): void
    {
        try {
            $ip = $request->ip();

            if (config('visit-analytics.anonymize_ip', true)) {
                $ip = $this->anonymizeIp($ip);
            }

            $whitelist = config('visit-analytics.whitelist', []);
            
            $payload = array_intersect_key(
                $request->query(), 
                array_flip($whitelist)
            );

            VisitLog::create([
                'ip_address' => $ip,
                'user_agent' => $request->userAgent(),
                'url'        => $request->fullUrl(),
                'referer'    => $request->headers->get('referer'),
                'payload'    => $payload ?: null,
            ]);
        } catch (\Throwable $e) {
            // We catch all errors but do nothing to ensure the main app 
            // stays functional even if analytics DB fails.
            // Optional: \Log::error($e->getMessage());
        }
    }

    /**
     * Mask the IP address for GDPR compliance.
     */
    protected function anonymizeIp(?string $ip): ?string
    {
        if (!$ip) {
            return $ip;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return preg_replace('/\.\d+$/', '.0', $ip);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return preg_replace('/:[0-9a-fA-F]+$/', ':0', $ip);
        }

        return $ip;
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }
}