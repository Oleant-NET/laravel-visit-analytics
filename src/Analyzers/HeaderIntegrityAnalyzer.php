<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class HeaderIntegrityAnalyzer
 *
 * Validates the presence and consistency of HTTP headers against standard browser profiles.
 * 
 * This analyzer checks if the request contains mandatory headers that legitimate browsers 
 * typically include. It uses a weighted scoring system where missing critical headers 
 * (like Fetch Metadata or Client Hints) significantly increase the threat score.
 */
class HeaderIntegrityAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyze the integrity of the request headers.
     *
     * @param VisitLog $log The visit log instance (target_headers is already cast to array).
     * @param AnalysisState $state The state object for collecting scores and evidence.
     * @param array $params Configuration for this analyzer (header_integrity section).
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        /** @var array $headers */
        $headers = $log->target_headers ?? [];
        $userAgent = $log->user_agent;

        // 1. Check if the overall header diversity is too low
        $this->evaluateHeaderDiversity($headers, $state, $params['min_total_headers'] ?? []);

        // 2. Evaluate individual header weights for missing elements
        $this->evaluateHeaderWeights($headers, $userAgent, $state, $params['weights'] ?? []);

        // 3. Log cookie absence as technical evidence if required
        if ($this->isHeaderTracked('cookie', $params) && !isset($headers['cookie'])) {
            $state->addEvidence('cookie_missing_in_headers', true);
        }

        // 4. Headers consistency
        $consistencyParams = $params['consistency_checks'] ?? $params;
        $this->analyzeConsistency($headers, $userAgent, $state, $consistencyParams ?? []);
    }

    /**
     * Evaluate the total number of headers present in the request.
     *
     * @param array $headers
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    private function evaluateHeaderDiversity(array $headers, AnalysisState $state, array $params): void
    {
        $minCount = $params['count'] ?? 5;
        $actualCount = count($headers);

        if ($actualCount < $minCount) {
            $state->add(
                $params['score'] ?? 40,
                'suspicious_minimal_headers',
                ['found_count' => $actualCount, 'required_count' => $minCount]
            );
        }
    }

    /**
     * Check for missing mandatory headers based on defined weights.
     * Special logic ensures Client Hints (sec-ch-) are only required for Chromium-based browsers.
     *
     * @param array $headers
     * @param string $userAgent
     * @param AnalysisState $state
     * @param array $weights
     * @return void
     */
    private function evaluateHeaderWeights(array $headers, string $userAgent, AnalysisState $state, array $weights): void
    {
        $headers = array_change_key_case($headers, CASE_LOWER);
        $uaLower = strtolower($userAgent);

        foreach ($weights as $headerName => $score) {
            $headerName = strtolower($headerName);

            if (str_starts_with($headerName, 'sec-ch-') && !str_contains($uaLower, 'chrome')) {
                continue;
            }

            if (!isset($headers[$headerName])) {
                $state->add($score, "missing_mandatory_header_{$headerName}");
            }
        }
    }

    /**
     * Analyzes header consistency and validates them against User-Agent data.
     * * @param array $headers Collected request headers.
     * @param string $userAgent The client's User-Agent string.
     * @param AnalysisState $state
     * @param array $weights Weights from configuration (consistency_checks).
     */
    /**
     * Analyzes header consistency to detect spoofing attempts and inconsistencies
     * between the User-Agent string and the provided Client Hints.
     *
     * @param array $headers The target headers extracted from the visit log.
     * @param string $userAgent The raw User-Agent string of the client.
     * @param AnalysisState $state The state object for tracking bot scores.
     * @param array $params Configuration parameters (consistency_checks section).
     * @return void
     */
    private function analyzeConsistency(array $headers, string $userAgent, AnalysisState $state, array $params): void
    {
        $headers = array_change_key_case($headers, CASE_LOWER);

        $uaLower = strtolower($userAgent);

        // 1. High-Entropy Header Detection
        $highEntropy = $params['high_entropy'] ?? [];
        if (($highEntropy['enabled'] ?? false) && !isset($headers['cookie'])) {
            foreach ($highEntropy['headers'] ?? [] as $header) {
                if (isset($headers[$header])) {
                    $state->add(
                        (int)($highEntropy['score'] ?? 30),
                        'bot_over_engineered'
                    );
                }
            }
        }

        // 2. Platform Consistency (OS Mismatch)
        $osCheck = $params['os_platform_mismatch'] ?? [];
        if (($osCheck['enabled'] ?? false) && isset($headers['sec-ch-ua-platform'])) {
            $osHint = strtolower($headers['sec-ch-ua-platform']);
            $isWindows = str_contains($uaLower, 'windows');
            $isMac = str_contains($uaLower, 'macintosh') || str_contains($uaLower, 'mac os x');

            if (($isWindows && str_contains($osHint, 'mac')) || ($isMac && str_contains($osHint, 'windows'))) {
                $state->add((int)($osCheck['score'] ?? 50), 'fingerprint_mismatch', ['reason' => 'os_conflict']);
            }

            // 3. Mobile vs Desktop conflict
            if (isset($headers['sec-ch-ua-mobile']) && $headers['sec-ch-ua-mobile'] === '?1') {
                if ($isMac || $isWindows) {
                    $state->add((int)($osCheck['score'] ?? 50), 'fingerprint_mismatch', ['reason' => 'mobile_desktop_conflict']);
                }
            }
        }

        // 4. Architecture Consistency
        $archCheck = $params['arch_architecture_mismatch'] ?? [];
        if (($archCheck['enabled'] ?? false) && isset($headers['sec-ch-ua-arch'])) {
            $arch = strtolower($headers['sec-ch-ua-arch']);

            // Alert on unsolicited high-entropy header on cold start
            if (!isset($headers['cookie'])) {
                $state->add((int)($archCheck['score'] ?? 30), 'bot_over_engineered', ['reason' => 'unsolicited_arch_header']);
            }

            // Cross-verify architecture
            if (str_contains($uaLower, 'intel') && str_contains($arch, 'arm')) {
                $state->add((int)($archCheck['score'] ?? 40), 'fingerprint_mismatch', ['reason' => 'arch_conflict']);
            }
        }
    }

    /**
     * Verify if a specific header is included in the tracking configuration.
     *
     * @param string $headerName
     * @param array $params
     * @return bool
     */
    private function isHeaderTracked(string $headerName, array $params): bool
    {
        return in_array($headerName, $params['target_headers'] ?? []);
    }
}