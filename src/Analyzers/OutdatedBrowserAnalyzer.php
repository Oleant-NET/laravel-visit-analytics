<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;


/**
 * Class OutdatedBrowserAnalyzer
 * 
 * Analyzes the browser version to detect legacy software or automation tools.
 * It prioritizes modern Client Hints (sec-ch-ua) for accuracy and falls back 
 * to User-Agent parsing if headers are unavailable.
 */
class OutdatedBrowserAnalyzer implements BotAnalyzerInterface
{
    /**
     * Executes the browser version check against configured thresholds.
     *
     * @param VisitLog $log The current visit log record.
     * @param AnalysisState $state The state object to collect scores and evidence.
     * @param array $params Configuration settings for this analyzer.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if (!($params['enabled'] ?? false)) {
            return;
        }

        // Attempt to extract browser details from Client Hints or User-Agent
        $browserData = $this->extractBrowserInfo($log);

        if (!$browserData) {
            return;
        }

        $browserName = $browserData['name'];
        $userVersion = $browserData['version'];
        $currentVersion = $params['current_versions'][$browserName] ?? null;

        // Skip if we don't have a reference version for this browser
        if (!$currentVersion || $userVersion <= 0) {
            return;
        }

        $diff = $currentVersion - $userVersion;
        
        // If the user's version is current or newer, no penalty is applied
        if ($diff <= 0) {
            return;
        }

        $appliedScore = 0;
        $appliedThreshold = '';

        /**
         * Iterate through scoring thresholds.
         * The loop overwrites previous values, ensuring only the highest 
         * applicable penalty is applied (e.g., 'ancient_lag' overrides 'minor_lag').
         */
        foreach ($params['scoring'] as $level => $rules) {
            if ($diff >= $rules['diff']) {
                $appliedScore = $rules['score'];
                $appliedThreshold = $level;
            }
        }
        if ($appliedScore > 0) {
            $state->add($appliedScore, 'outdated_browser', [
                'browser'         => $browserName,
                'user_version'    => $userVersion,
                'target_version'  => $currentVersion,
                'version_lag'     => $diff,
                'severity_level'  => $appliedThreshold
            ]);
        }
    }

    /**
     * Extracts browser name and major version.
     * 
     * Uses 'sec-ch-ua' Client Hints as the primary source for high reliability
     * in modern environments, with a fallback to traditional User-Agent string.
     *
     * @param VisitLog $log
     * @return array{name: string, version: int}|null
     */
    private function extractBrowserInfo(VisitLog $log): ?array
    {
        // 1. Primary: Extract from Client Hints (sec-ch-ua)
        $headers = $log->target_headers;
        $ch = $headers['sec-ch-ua'] ?? '';
        
        if ($ch && preg_match('/"Google Chrome";v="(\d+)"/', $ch, $matches)) {
            return [
                'name'    => 'chrome', 
                'version' => (int) $matches[1]
            ];
        }

        // 2. Secondary: Fallback to User-Agent parsing
        if (preg_match('/Chrome\/(\d+)/', $log->user_agent, $matches)) {
            return [
                'name'    => 'chrome', 
                'version' => (int) $matches[1]
            ];
        }

        return null;
    }
}