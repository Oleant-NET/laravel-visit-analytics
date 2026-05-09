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
        if (!($params['enabled'] ?? false)) {
            return;
        }

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
        foreach ($weights as $headerName => $score) {
            // Optimization: Skip Client Hints verification for non-Chrome/Edge browsers
            if (str_starts_with($headerName, 'sec-ch-') && stripos($userAgent, 'Chrome') === false) {
                continue;
            }

            if (!isset($headers[$headerName])) {
                $state->add($score, "missing_mandatory_header_{$headerName}");
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