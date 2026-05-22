<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class RefererAnalyzer
 * * Analyzes Referer header integrity and sequential direct hits.
 * Detects "Snowball" effect for direct visits and impossible navigation loops.
 */
class RefererAnalyzer implements BotAnalyzerInterface
{
    /**
     * Executes the referer analysis.
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $weights = $params['weights'] ?? [];
        $cumulativeConfig = $params['cumulative'] ?? [];

        // 1. Handle missing Referer (Direct Navigation or Bot Anomaly)
        if (empty($log->referer)) {
            $this->analyzeMissingReferer($log, $state, $weights, $cumulativeConfig);
            return;
        }

        // 2. Handle existing Referer
        $this->analyzeExistingReferer($log, $state, $weights, $params);
    }

    /**
     * Logic for Direct Navigation (No Referer) leveraging Fetch Metadata.
     */
    protected function analyzeMissingReferer(VisitLog $log, AnalysisState $state, array $weights, array $cumulativeConfig): void
    {
        // Target headers are automatically cast to an array by the Eloquent model
        $headers = $log->target_headers ?? [];
        $fetchSite = $headers['sec-fetch-site'] ?? null;

        $basePoints = 0;
        $reason = 'missing_referer';
        $meta = ['referer_source' => 'direct_navigation'];

        if ($fetchSite !== null) {
            if ($fetchSite === 'same-origin') {
                
                // --- TIMED DIRECT -> REFRESH PAIR DETECTION ---
                $windowMinutes = (int)($cumulativeConfig['no_referer_window_minutes'] ?? 10);
                $sessionStart = $log->created_at->copy()->subMinutes($windowMinutes);

                $firstLog = VisitLog::withoutGlobalScopes()
                    ->where('ip_address', $log->ip_address)
                    ->where('id', '<', $log->id) 
                    ->where('created_at', '>=', $sessionStart->toDateTimeString())
                    ->orderBy('id', 'asc')
                    ->first();

                if ($firstLog) {
                    $firstHeaders = $firstLog->target_headers ?? [];
                    $firstFetchSite = $firstHeaders['sec-fetch-site'] ?? null;

                    if ($firstFetchSite === 'none') {
                        return;
                    }
                }
                // -----------------------------------------------

                // Anomaly: Browser claims a link was clicked, but Referer is missing.
                $basePoints = (int)($weights['no_referer'] ?? 35);
                $reason = 'missing_referer_on_navigation';
                $meta['sec_fetch_site'] = $fetchSite;

            } elseif ($fetchSite === 'cross-site') {
                // Anomaly: Clicked from an external site, but Referer header was missing
                $basePoints = (int)($weights['no_referer'] ?? 35);
                $reason = 'missing_referer_on_navigation';
                $meta['sec_fetch_site'] = $fetchSite;

            } elseif ($fetchSite === 'none') {
                // Legitimate initial direct navigation (typed URL, bookmark)
                $basePoints = 0;
            }
        } else {
            // Fallback for older browsers or primitive bots lacking Fetch Metadata support
            $basePoints = (int)($weights['no_referer'] ?? 35);
        }

        if ($basePoints > 0) {
            $state->add($basePoints, $reason, $meta);
        }

        // "Snowball" logic: only increments for repeated, consecutive direct hits ('none' or fallback)
        if (($cumulativeConfig['enabled'] ?? false) && ($fetchSite === 'none' || $fetchSite === null)) {
            $windowMinutes = (int)($cumulativeConfig['no_referer_window_minutes'] ?? 10);
            
            $directHitsHistory = VisitLog::where('ip_address', $log->ip_address)
                ->where(function($q) {
                    $q->whereNull('referer')->orWhere('referer', '');
                })
                ->where('created_at', '>=', $log->created_at->copy()->subMinutes($windowMinutes));

            if ($log->exists) {
                $directHitsHistory->where('id', '<', $log->id);
            }

            $directHitsCount = $directHitsHistory->count();

            if ($directHitsCount > 0) {
                $multiplier = (int)($cumulativeConfig['no_referer_increment'] ?? 20);
                $state->add($directHitsCount * $multiplier, 'referer_snowball', [
                    'sequential_direct_hits' => $directHitsCount
                ]);
            }
        }
    }

    /**
     * Logic for suspicious existing Referer values.
     */
    protected function analyzeExistingReferer(VisitLog $log, AnalysisState $state, array $weights, array $params): void
    {
        // Port Leak Detection (e.g., navigation from hosting panels)
        $leakPorts = $params['port_leak'] ?? [2082, 2083, 2086, 2087, 8888, 8443];
        foreach ($leakPorts as $port) {
            if (str_contains($log->referer, ":$port")) {
                $state->add((int)($weights['port_leak'] ?? 45), 'port_leak', [
                    'leaked_port' => $port
                ]);
                break;
            }
        }

        // Self-Referer Loop Detection (Page refers to itself)
        $urlParts = parse_url($log->url);
        $refParts = parse_url($log->referer);

        if (($urlParts['host'] ?? '') === ($refParts['host'] ?? '')) {
            
            $headers = $log->target_headers ?? [];
            $fetchSite = $headers['sec-fetch-site'] ?? null;

            // If the site is calling itself (same-origin), it is often legitimate
            // (e.g., AJAX requests, anchor navigation, or query parameter changes)
            if ($fetchSite === 'same-origin') {
                return; // Skip the check; do not consider this a loop
            }
            
            $cleanUrl = rtrim(str_replace(['https://', 'http://', 'www.'], '', $log->url), '/');
            $cleanRef = rtrim(str_replace(['https://', 'http://', 'www.'], '', $log->referer), '/');

            if ($cleanUrl === $cleanRef) {
                // Verify if the user has actually visited this URL before in this session
                $wasAlreadyHere = VisitLog::where('ip_address', $log->ip_address)
                    ->where('url', $log->url)
                    ->where('id', '<', $log->id)
                    ->exists();

                if (!$wasAlreadyHere) {
                    // Critical anomaly: you cannot be referred by a page you haven't visited yet
                    $state->add(100, 'impossible_self_referer', [
                        'anomaly' => 'self_ref_on_first_visit'
                    ]);
                } else {
                    // Standard suspicious referer loop
                    $state->add((int)($weights['referer_loop'] ?? 50), 'referer_loop');
                }
            }
        }
    }
}