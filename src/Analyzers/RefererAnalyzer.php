<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class RefererAnalyzer
 * 
 * Analyzes Referer header integrity and sequential direct hits.
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

        // 1. Handle missing Referer (Direct Navigation)
        if (empty($log->referer)) {
            $this->analyzeMissingReferer($log, $state, $weights, $cumulativeConfig);
            return;
        }

        // 2. Handle existing Referer
        $this->analyzeExistingReferer($log, $state, $weights, $params);
    }

    /**
     * Logic for Direct Navigation (No Referer).
     */
    protected function analyzeMissingReferer(VisitLog $log, AnalysisState $state, array $weights, array $cumulativeConfig): void
    {
        // Base penalty for missing referer
        $basePoints = (int)($weights['no_referer'] ?? 35);
        $state->add($basePoints, 'missing_referer', [
            'referer_source' => 'direct_navigation'
        ]);

        // "Snowball" logic: increment penalty for repeated direct hits
        if ($cumulativeConfig['enabled'] ?? false) {
            $windowMinutes = (int)($cumulativeConfig['no_referer_window_minutes'] ?? 10);
            
            $directHitsHistory = VisitLog::where('ip_address', $log->ip_address)
                ->where(function($q) {
                    $q->whereNull('referer')->orWhere('referer', '');
                })
                ->where('created_at', '>=', now()->subMinutes($windowMinutes))
                ->where('id', '<', $log->id)
                ->count();

            if ($directHitsHistory > 0) {
                $multiplier = (int)($cumulativeConfig['no_referer_increment'] ?? 20);
                $state->add($directHitsHistory * $multiplier, 'referer_snowball', [
                    'sequential_direct_hits' => $directHitsHistory
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
        $protocols = ['https://', 'http://', 'www.'];
        $cleanUrl = rtrim(str_replace($protocols, '', $log->url), '/');
        $cleanRef = rtrim(str_replace($protocols, '', $log->referer), '/');

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