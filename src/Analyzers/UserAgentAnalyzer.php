<?php 

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class UserAgentAnalyzer
 * 
 * Advanced evaluation of User-Agent integrity.
 * Combines regex pattern matching, keyword scanning, and cross-verification 
 * with modern Client Hints (Sec-CH-UA).
 */
class UserAgentAnalyzer implements BotAnalyzerInterface
{
    /**
     * Main entry point for UA analysis.
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $ua = trim((string)$log->user_agent);
        $weights = $params['weights'] ?? [];

        // 1. Critical anomaly: Missing or empty User-Agent
        if (empty($ua)) {
            $state->add(
                (int)($weights['missing_ua'] ?? 100), 
                'missing_user_agent', 
                ['ua_status' => 'empty_header']
            );
            return;
        }

        // 2. Run regex-based patterns and verification
        $this->analyzeUAPatterns($ua, $log, $state, $params);

        // 3. Scan for UA engines (Gesko, Trident, etc.)
        $this->analyzeUAEngine($ua, $state, $params);
    }

    /**
     * Analyzes the User-Agent against configured regex patterns.
     */
    protected function analyzeUAPatterns(string $ua, VisitLog $log, AnalysisState $state, array $params): void
    {
        $patterns = $params['ua_regex_patterns'] ?? [];
        $headers = is_array($log->target_headers) ? $log->target_headers : [];
        $weights = $params['weights'] ?? [];

        foreach ($patterns as $key => $data) {
            $pattern = $data['pattern'] ?? $data;
            $weight  = $data['weight'] ?? 0;
            $needsVerification = $data['requires_verification'] ?? false;

            // Normalize delimiter for safe preg_match
            $delimiter = (str_starts_with($pattern, '/') && (preg_match('/\/[imsxu]*$/', $pattern))) 
                ? $pattern 
                : '/' . $pattern . '/i';

            if (@preg_match($delimiter, $ua)) {
                if ($needsVerification) {
                    // Cross-reference with Client Hints / Fetch Metadata
                    if (!$this->isSignatureVerified($ua, $headers, $params)) {
                        $failPoints = (int)($weights['verification_failed'] ?? 80);
                        $state->add($failPoints, "verification_failed_{$key}", [
                            'matched_pattern' => $pattern,
                            'check' => 'client_hints_mismatch'
                        ]);
                    } else {
                        // Signature is consistent with modern browser behavior
                        continue;
                    }
                } else {
                    $state->add((int)$weight, "ua_match_{$key}", [
                        'matched_pattern' => $pattern
                    ]);
                }
            }
        }
    }

    /**
     * Scans the User-Agent for valid browser engines.
     * If no valid engine is found, applies a penalty.
     */
    protected function analyzeUAEngine(string $ua, AnalysisState $state, array $params): void
    {
        $engines = $params['browser_engines'] ?? [];
        
        // Check if the UA contains at least one known browser engine
        foreach ($engines as $engine) {
            if (str_contains($ua, $engine)) {
                // Valid engine found, user is likely a real browser
                return;
            }
        }

        // No engine found: apply penalty and flag as suspicious
        $state->add(
            (int)($params['weights']['ua_suspicious'] ?? 50),
            'ua_suspicious',
            ['reason' => 'missing_browser_engine']
        );
    }

    /**
     * Deep-verification layer for modern Chromium browsers.
     * Ensures consistency between UA string and High-Entropy Client Hints.
     */
    protected function isSignatureVerified(string $ua, array $headers, array $params): bool
    {
        // Normalize headers to lowercase
        $headers = array_change_key_case($headers, CASE_LOWER);

        // 1. Extract Major Version from User-Agent
        preg_match('/(?:Chrome|Edg|Chromium)\/([0-9]+)/', $ua, $uaMatches);
        $uaMajor = $uaMatches[1] ?? null;

        // 2. Mandatory check: Modern Chromium (v100+) MUST provide Client Hints
        if ($uaMajor && (int)$uaMajor >= 100 && !isset($headers['sec-ch-ua'])) {
            return false;
        }

        // 3. Version Consistency Check
        if ($uaMajor && isset($headers['sec-ch-ua'])) {
            $expectedVersion = "v=\"$uaMajor\"";
            if (!str_contains($headers['sec-ch-ua'], $expectedVersion)) {
                return false; 
            }
        }

        // 4. Operating System Consistency Check (sec-ch-ua-platform)
        if (isset($headers['sec-ch-ua-platform'])) {
            $platform = trim($headers['sec-ch-ua-platform'], '" ');
            $osMap = $params['os_mapping'] ?? [];

            foreach ($osMap as $uaToken => $hintToken) {
                if (stripos($ua, (string)$uaToken) !== false) {
                    if ($platform !== $hintToken) {
                        return false; 
                    }
                    break;
                }
            }
        }

        return true;
    }
}