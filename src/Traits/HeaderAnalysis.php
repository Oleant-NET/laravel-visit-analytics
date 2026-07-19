<?php

namespace Oleant\VisitAnalytics\Traits;

use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Trait HeaderAnalysis
 * 
 * Provides core analysis methods for request header integrity.
 * This trait allows individual rule classes to remain lightweight while
 * sharing complex header inspection logic.
 */
trait HeaderAnalysis
{
    /**
     * Evaluates the diversity (total count) of headers present in the request.
     * 
     * @param array $headers The request headers array.
     * @param AnalysisState $state The current analysis state to record violations.
     * @param array $params Configuration parameters: ['min_total_headers' => int, 'score' => int]
     * @return void
     */
    protected function evaluateHeaderDiversity(array $headers, AnalysisState $state, array $params): void
    {
        $actualCount = count($headers);
        $minCount = $params['min_total_headers'] ?? 5;

        if ($actualCount < $minCount) {
            $state->add($params['score'] ?? 40, 'suspicious_minimal_headers', [
                'found_count'    => $actualCount,
                'required_count' => $minCount
            ]);
        }
    }

    /**
     * Validates the presence of mandatory headers based on defined weights.
     * Automatically skips 'sec-ch-' headers for non-Chromium browsers to prevent false positives.
     * 
     * @param array $headers The request headers array.
     * @param string $userAgent The raw User-Agent string.
     * @param AnalysisState $state The current analysis state.
     * @param array $scores_without Associative array of headers and their corresponding threat scores.
     * @return void
     */
    protected function evaluateHeaderWeights(array $headers, string $userAgent, AnalysisState $state, array $scores_without): void
    {
        $headers = array_change_key_case($headers, CASE_LOWER);
        $uaLower = strtolower($userAgent);
        $isChromium = str_contains($uaLower, 'chrome');

        foreach ($scores_without as $headerName => $score) {
            $h = strtolower($headerName);
            
            // Skip Client Hints if the browser is not Chromium
            if (str_starts_with($h, 'sec-ch-') && !$isChromium) {
                continue;
            }

            if (!isset($headers[$h])) {
                $state->add($score, "missing_mandatory_header_{$h}");
            }
        }
    }

    /**
     * Analyzes consistency between headers, User-Agent, and Client Hints.
     * Detects high-entropy spoofing, OS platform mismatches, and architecture conflicts.
     * 
     * @param array $headers The request headers array.
     * @param string $userAgent The raw User-Agent string.
     * @param AnalysisState $state The current analysis state.
     * @param array $params Configuration parameters for consistency checks.
     * @return void
     */
    protected function analyzeConsistency(array $headers, string $userAgent, AnalysisState $state, array $params): void
    {
        $headers = array_change_key_case($headers, CASE_LOWER);
        $uaLower = strtolower($userAgent);
        $hasCookie = isset($headers['cookie']);

        // 1. High-Entropy Header Detection
        if (!$hasCookie && isset($params['high_entropy'])) {
            $highEntropy = $params['high_entropy'];
            foreach ($highEntropy['headers'] ?? [] as $header) {
                if (isset($headers[$header])) {
                    $state->add((int)($highEntropy['score'] ?? 20), 'bot_over_engineered');
                }
            }
        }

        // 2. Platform Consistency (OS Mismatch)
        if (isset($headers['sec-ch-ua-platform'], $params['os_platform_mismatch_score'])) {
            $osHint = strtolower($headers['sec-ch-ua-platform']);
            $isWin = str_contains($uaLower, 'windows');
            $isMac = str_contains($uaLower, 'macintosh') || str_contains($uaLower, 'mac os x');

            if (($isWin && str_contains($osHint, 'mac')) || ($isMac && str_contains($osHint, 'windows'))) {
                $state->add((int)$params['os_platform_mismatch_score'], 'fingerprint_mismatch', ['reason' => 'os_conflict']);
            }
        }

        // 3. Architecture Consistency
        if (isset($headers['sec-ch-ua-arch'], $params['arch_architecture_mismatch_score'])) {
            $arch = strtolower($headers['sec-ch-ua-arch']);
            
            // Flag unsolicited high-entropy headers on cold requests
            if (!$hasCookie) {
                $state->add((int)$params['arch_architecture_mismatch_score'], 'bot_over_engineered', ['reason' => 'unsolicited_arch_header']);
            }

            // Cross-verify architecture
            if (str_contains($uaLower, 'intel') && str_contains($arch, 'arm')) {
                $state->add((int)$params['arch_architecture_mismatch_score'], 'fingerprint_mismatch', ['reason' => 'arch_conflict']);
            }
        }
    }
}