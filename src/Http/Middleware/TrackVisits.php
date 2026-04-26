<?php

namespace Oleant\VisitAnalytics\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Oleant\VisitAnalytics\Models\VisitLog;
use Symfony\Component\HttpFoundation\Response;
use Jaybizzle\CrawlerDetect\CrawlerDetect;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\IpUtils;

class TrackVisits
{
    /**
     * Handle tasks after the response has been sent to the browser.
     */
    public function terminate(Request $request, Response $response): void
    {
        try {
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

            // 2. IP & Subnet Exclusion (Supports Single IP and CIDR notation)
            $excludedIps = config('visit-analytics.exclude.ips', []);
            if (!empty($excludedIps) && IpUtils::checkIp($request->ip(), $excludedIps)) {
                return;
            }

            // 3. Specific emails (admins, publischers etc.) Exclusion
            $user = auth()->user();
            if ($user && in_array($user->email, config('visit-analytics.exclude.emails', []))) {
                return;
            }

            // 4. Auth Filter (Ignore logged-in users if configured)
            if (config('visit-analytics.exclude.ignore_authenticated', false) && auth()->check()) {
                return;
            }

            // 5. Bot Detection
            if (!config('visit-analytics.track_bots', false)) {
                $crawlerDetect = new CrawlerDetect;
                if ($crawlerDetect->isCrawler($request->userAgent())) {
                    return;
                }
            }

            $this->logVisit($request);
        } catch (\Throwable $e) {
            \Log::error($e->getMessage());
        }
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

        // For IPv4: Mask the last byte (e.g., 192.168.1.15 -> 192.168.1.0)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return long2ip(ip2long($ip) & ip2long('255.255.255.0'));
        }

        // For IPv6: Mask to /64 network (e.g., 2001:db8:85a3:08d3:1319:8a2e:0370:7334 -> 2001:db8:85a3:8d3::0)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);
            return implode(':', array_slice($parts, 0, 4)) . '::0';
        }

        return $ip;
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }
}