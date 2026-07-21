<?php

namespace Oleant\VisitAnalytics\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\IpAnonymizerService;

class TrackVisits
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next): mixed
    {
        return $next($request);
    }

    /**
     * Handle tasks after the response has been sent to the browser.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return void
     */
    public function terminate(Request $request, Response $response): void
    {
        $config = config('visit-analytics-collection', []);

        try {
            if ($this->shouldIgnore($request, $config)) {
                return;
            }

            $this->logVisit($request, $config);
        } catch (\Throwable $e) {
            Log::error('VisitAnalytics Middleware Error: ' . $e->getMessage());
        }
    }

    /**
     * Determine if the incoming request should be ignored based on the configuration.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<string, mixed>  $config
     * @return bool
     */
    protected function shouldIgnore(Request $request, array $config): bool
    {
        $excludeConfig = $config['exclude'] ?? [];

        return $this->isExcludedPath($request, $excludeConfig['paths'] ?? [])
            || $this->isExcludedIp($request->ip(), $excludeConfig['ips'] ?? [])
            || $this->isExcludedUser($excludeConfig);
    }

    /**
     * Check if the request path or its referer matches the exclusion list.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<int, string>  $excludePaths
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
            if ($request->is($path) || ($refererPath && Str::is($path, $refererPath))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the visitor's IP address is within the exclusion list.
     *
     * @param  string|null  $ip
     * @param  array<int, string>  $excludedIps
     * @return bool
     */
    protected function isExcludedIp(?string $ip, array $excludedIps): bool
    {
        return !empty($excludedIps) && IpUtils::checkIp($ip, $excludedIps);
    }

    /**
     * Check if the authenticated user meets exclusion criteria.
     *
     * @param  array<string, mixed>  $excludeConfig
     * @return bool
     */
    protected function isExcludedUser(array $excludeConfig): bool
    {
        if (!auth()->check()) {
            return false;
        }

        $user = auth()->user();

        $excludedEmails = $excludeConfig['emails'] ?? [];
        if ($user && in_array($user->email, $excludedEmails)) {
            return true;
        }

        return (bool) ($excludeConfig['ignore_authenticated'] ?? false);
    }

    /**
     * Extract and log the visitor's data to the database.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<string, mixed>  $config
     * @return void
     */
    protected function logVisit(Request $request, array $config): void
    {
        $anonymizer = app(IpAnonymizerService::class);
        $ip = $anonymizer->handle($request->ip());

        $whitelist = $config['whitelist_params'] ?? [];
        $payload = array_intersect_key(
            $request->query(), 
            array_flip($whitelist)
        );

        $targetHeaders = $this->extractTargetHeaders($request, $config);
        
        // Ensure consistent hashing by sorting headers
        $fingerprintData = $targetHeaders;
        ksort($fingerprintData);
        $fingerprintHash = hash('sha256', $request->userAgent() . '|' . json_encode($fingerprintData));

        VisitLog::create([
            'ip_address'       => $ip,
            'user_agent'       => $request->userAgent(),
            'target_headers'   => $targetHeaders,
            'fingerprint_hash' => $fingerprintHash,
            'url'              => $request->fullUrl(),
            'referer'          => $request->headers->get('referer'),
            'payload'          => !empty($payload) ? $payload : null,
            'created_at'       => now(),
        ]);
    }

    /**
     * Extracts and normalizes target HTTP headers.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    protected function extractTargetHeaders(Request $request, array $config): array
    {
        $targetHeaders = $config['target_headers'] ?? [];
        $cookieMode = $config['cookie_mode'] ?? 'exists';
        $extracted = [];

        foreach ($targetHeaders as $header) {
            $headerName = strtolower(trim($header));

            if (!$request->headers->has($headerName)) {
                continue;
            }

            if ($headerName === 'cookie') {
                if ($cookieMode === 'full') {
                    $extracted[$headerName] = $request->header($headerName);
                } elseif ($cookieMode === 'exists') {
                    $extracted['cookies_present'] = true;
                }
                continue;
            }

            $extracted[$headerName] = $request->header($headerName);
        }

        return $extracted;
    }
}