<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Base;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Abstract Class AbstractBotnetRule
 * 
 * Base class for all behavioral analysis rules. Provides shared utility methods
 * for request inspection and data normalization.
 */
abstract class AbstractHeaderIntegrityRule implements RuleInterface
{
    /**
     * Evaluate the total number of headers present in the request.
     *
     * @param array $headers
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    protected function evaluateHeaderDiversity(array $headers, AnalysisState $state, array $params): void
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
    protected function evaluateHeaderWeights(array $headers, string $userAgent, AnalysisState $state, array $weights): void
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
     * Analyzes header consistency to detect spoofing attempts and inconsistencies
     * between the User-Agent string and the provided Client Hints.
     *
     * @param array $headers The target headers extracted from the visit log.
     * @param string $userAgent The raw User-Agent string of the client.
     * @param AnalysisState $state The state object for tracking bot scores.
     * @param array $params Configuration parameters (consistency_checks section).
     * @return void
     */
    protected function analyzeConsistency(array $headers, string $userAgent, AnalysisState $state, array $params): void
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
    protected function isHeaderTracked(string $headerName, array $params): bool
    {
        return in_array($headerName, $params['target_headers'] ?? []);
    }
}