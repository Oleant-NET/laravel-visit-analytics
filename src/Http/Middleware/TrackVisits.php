<?php

namespace Oleant\VisitAnalytics\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Oleant\VisitAnalytics\Models\VisitLog;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\IpUtils;

class TrackVisits
{
    /**
     * Configuration file
     * @var array<string, mixed>
     */
    protected array $config = [];

    /**
     * Class Constructor
     */
    public function __construct()
    {
        $this->config = config('visit-analytics.collection');
    }

    /**
     * Handle tasks after the response has been sent to the browser.
     */
    public function terminate(Request $request, Response $response): void
    {
        try {
            if ($this->shouldIgnore($request)) {
                return;
            }

            $this->logVisit($request);
        } catch (\Throwable $e) {
            \Log::error($e->getMessage());
        }
    }

    /**
     * Determine if the incoming request should be ignored based on the configuration.
     *
     * This method aggregates various filtration layers including path patterns, 
     * referer integrity, IP whitelisting/blacklisting, and user authentication status.
     *
     * @param \Illuminate\Http\Request $request The current incoming request instance.
     * @return bool Returns true if the request matches any exclusion criteria, false otherwise.
     */
    protected function shouldIgnore(Request $request): bool
    {
        $excludeConfig = $this->config['exclude'] ?? [];

        // 1. Path & Referer Filtering
        // Skips tracking if the current URL or the originating page matches excluded patterns.
        if ($this->isExcludedPath($request, $excludeConfig['paths'] ?? [])) {
            return true;
        }

        // 2. IP Address & Subnet Filtering
        // Supports single IP addresses and CIDR notation (e.g., '192.168.1.0/24').
        if ($this->isExcludedIp($request->ip(), $excludeConfig['ips'] ?? [])) {
            return true;
        }

        // 3. User-Based Filtering
        // Evaluates the authenticated user's email and global authentication settings.
        if ($this->isExcludedUser($excludeConfig)) {
            return true;
        }

        return false;
    }

    /**
     * Check if the request path or its referer matches the exclusion list.
     *
     * @param \Illuminate\Http\Request $request
     * @param array<int, string> $excludePaths List of path patterns (glob-style).
     * @return bool
     */
    protected function isExcludedPath(Request $request, array $excludePaths): bool
    {
        if (empty($excludePaths)) {
            return false;
        }

        $referer = $request->headers->get('referer');
        $refererPath = $referer ? ltrim((string)parse_url($referer, PHP_URL_PATH), '/') : null;

        foreach ($excludePaths as $path) {
            // Match current request URL
            if ($request->is($path)) {
                return true;
            }

            // Match referer to catch background requests (e.g., Livewire, AJAX)
            if ($refererPath && Str::is($path, $refererPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the visitor's IP address is within the exclusion list.
     *
     * @param string|null $ip
     * @param array<int, string> $excludedIps
     * @return bool
     */
    protected function isExcludedIp(?string $ip, array $excludedIps): bool
    {
        return !empty($excludedIps) && IpUtils::checkIp($ip, $excludedIps);
    }

    /**
     * Check if the authenticated user meets exclusion criteria.
     *
     * @param array<string, mixed> $config The 'exclude' section of the config.
     * @return bool
     */
    protected function isExcludedUser(array $excludeConfig): bool
    {
        if (!auth()->check()) {
            return false;
        }

        $user = auth()->user();

        // Verify against specific administrative or internal email addresses
        $excludedEmails = $excludeConfig['emails'] ?? [];
        if ($user && in_array($user->email, $excludedEmails)) {
            return true;
        }

        // Check if all authenticated users should be ignored
        if ($excludeConfig['ignore_authenticated'] ?? false) {
            return true;
        }

        return false;
    }

    /**
     * Extract and log the visitor's data to the database.
     */
    protected function logVisit(Request $request): void
    {
        try {
            $ip = $request->ip();

            if ($this->config['anonymize_ip'] ?? true) {
                $ip = $this->anonymizeIp($ip);
            }

            $whitelist = $this->config['whitelist'] ?? [];
            
            $payload = array_intersect_key(
                $request->query(), 
                array_flip($whitelist)
            );

            VisitLog::create([
                'ip_address' => $ip,
                'user_agent' => $request->userAgent(),
                'target_headers' => $this->extractTargetHeaders($request),
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

    /**
     * Extracts and normalizes target HTTP headers based on the package configuration.
     * 
     * This method filters request headers to capture specific metadata (e.g., Client Hints).
     * It implements a privacy-aware strategy for 'Cookie' headers: depending on the 
     * 'cookie_mode' setting, it can store the full header, a boolean existence flag, 
     * or skip it entirely to prevent sensitive session data leaks.
     *
     * @param \Illuminate\Http\Request $request The incoming HTTP request.
     * @return array<string, mixed> Key-value pairs of normalized headers or status flags.
     */
    protected function extractTargetHeaders(Request $request): array
    {
        $targetHeaders = $this->config['target_headers'] ?? [];
        $cookieMode = $this->config['cookie_mode'] ?? 'exists';
        $extracted = [];

        foreach ($targetHeaders as $header) {
            $headerName = strtolower(trim($header));

            if (!$request->headers->has($headerName)) {
                continue;
            }

            /**
             * State persistence check with privacy handling.
             * We verify if the client supports and returns cookies, but handle 
             * the actual data according to the configured privacy mode.
             */
            if ($headerName === 'cookie') {
                if ($cookieMode === 'full') {
                    $extracted[$headerName] = $request->header($headerName);
                } elseif ($cookieMode === 'exists') {
                    $extracted['cookies_present'] = true;
                }
                // If mode is 'none', we explicitly skip adding it to the result
                continue;
            }

            // Standard header extraction for Client Hints, Fetch Metadata, etc.
            $extracted[$headerName] = $request->header($headerName);
        }

        return $extracted;
    }

    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }
}