<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;

/**
 * Class FingerprintAnonymizerService
 *
 * Provides functionality to anonymize visitor fingerprints by processing 
 * User-Agents, request headers, and fingerprint hashes to maintain privacy.
 */
class FingerprintAnonymizerService
{
    /**
     * Orchestrator: executes all anonymization procedures for a given log entry.
     *
     * @param VisitLog $log
     * @return array
     */
    public function handle(VisitLog $log): array
    {
        $config = config('visit-analytics.collection.anonymization', []);
        
        $updates = [];

        if ($config['anonymize_ua'] ?? true) {
            $updates['user_agent'] = $this->anonymizeUserAgent($log);
        }

        if ($config['anonymize_headers'] ?? true) {
            $updates['target_headers'] = $this->anonymizeHeaders($log->target_headers);
        }

        if ($config['anonymize_fingerprint_hash'] ?? true) {
            $updates['fingerprint_hash'] = $this->config['fingerprint_placeholder'] ?? 'anonym-sha256-ready';
        }

        return $updates;
    }

    /**
     * Anonymize or parse the User-Agent string for the VisitLog.
     *
     * Returns a simplified representation of the browser, platform, and device type.
     * If the log is flagged as a bot, returns a standardized bot label.
     * Uses Client Hints if available, falling back to legacy User-Agent string parsing.
     *
     * @param VisitLog $log The visit log instance containing UA and header data.
     * @return string A formatted string describing the client (e.g., "Chrome / Windows (Desktop)" or "Bot UA").
     */
    protected function anonymizeUserAgent(VisitLog $log): string
    {
        // Handle bot status
        if ($log->is_bot) {
            return $log->is_official_bot ? 'Legal Bot UA' : 'Bot UA';
        }

        $headers = $log->target_headers ?? [];
        $ua = $log->user_agent ?? '';

        // Use Client Hints if available
        if (!empty($headers['sec-ch-ua-platform'])) {
            $platform = str_replace('"', '', $headers['sec-ch-ua-platform']);
            
            // Refined brand selection
            $rawBrands = $headers['sec-ch-ua'] ?? 'Browser';
            $brand = 'Browser';
            foreach (explode(',', $rawBrands) as $b) {
                $b = str_replace('"', '', trim($b));
                if (stripos($b, 'Not)A;Brand') !== false) {
                    continue;
                }
                $brand = explode(';', $b)[0];
                break;
            }

            $mobile = ($headers['sec-ch-ua-mobile'] ?? '?0') === '?1' ? 'Mobile' : 'Desktop';
            
            return "{$brand} / {$platform} ({$mobile})";
        }

        // Determine OS from User-Agent string
        $os = 'Unknown OS';
        if (stripos($ua, 'Android') !== false) { $os = 'Android'; }
        elseif (stripos($ua, 'iPhone') !== false || stripos($ua, 'iPad') !== false) { $os = 'iOS'; }
        elseif (stripos($ua, 'Windows NT') !== false) { $os = 'Windows'; }
        elseif (stripos($ua, 'Macintosh') !== false) { $os = 'macOS'; }
        elseif (stripos($ua, 'Linux') !== false) { $os = 'Linux'; }

        // Determine Browser from User-Agent string
        $browser = 'Unknown';
        foreach (['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'] as $b) {
            if (stripos($ua, $b) !== false) {
                $browser = $b;
                break;
            }
        }

        return "{$browser} / {$os} (Legacy)";
    }

    /**
     * Anonymizes request headers by keeping only the list of header names.
     *
     * @param array|null $headers
     * @return array|null
     */
    protected function anonymizeHeaders(?array $headers): ?array
    {
        if (empty($headers)) return null;

        // Returns an indexed array of header names
        return array_keys($headers);
    }
}