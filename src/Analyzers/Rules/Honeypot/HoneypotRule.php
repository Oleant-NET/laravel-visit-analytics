<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Honeypot;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HoneypotRule
 * 
 * Evaluates scans of service paths and configuration files and assigns them threat scores.
 */
class HoneypotRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        /** 
        * @var array $honeypots List of URL fragments used as traps (e.g., '/admin/config.php') 
        **/
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