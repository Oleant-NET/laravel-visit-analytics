<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class HoneypotAnalyzer
 * 
 * Detects automated scanners and crawlers that attempt to access 
 * forbidden or "hidden" paths specifically designed as traps.
 * Since real users should never interact with these paths, a hit 
 * usually results in an immediate critical bot score.
 */
class HoneypotAnalyzer implements BotAnalyzerInterface
{
    /**
     * Checks if the requested URL matches any defined honeypot traps.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Package configuration.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        /** @var array $honeypots List of URL fragments used as traps (e.g., '/admin/config.php') */
        $honeypots = $params['honeypot_paths'] ?? [];

        foreach ($honeypots as $path) {
            // Check if the current URL contains a forbidden path segment
            if (!empty($path) && str_contains($log->url, $path)) {
                
                // Fetch the penalty weight, defaulting to 100 for honeypot hits
                $points = (int)($params['weights']['honeypot'] ?? 100);

                /**
                 * Add the critical score and record the exact URL that triggered the trap.
                 */
                $state->add($points, 'honeypot_trap', [
                    'honeypot_url' => $log->url,
                    'matched_trap' => $path
                ]);

                /**
                 * Stop processing this analyzer.
                 * Note: If points >= 100, the Service will also trigger an early exit 
                 * for the entire analysis chain.
                 */
                break;
            }
        }
    }
}
