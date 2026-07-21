<?php

namespace Oleant\VisitAnalytics\Rules\UserAgent;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class BrowserEngineRule
 * 
 * Inspects the User-Agent string to ensure it contains a recognized browser engine.
 * The absence of a standard rendering engine signature is highly characteristic 
 * of custom scripts, scrapers, or poorly disguised bots.
 */
class BrowserEngineRule implements RuleInterface
{
    /**
     * Applies the rule to verify the presence of known browser engine signatures.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Package configuration: requires 'browser_engines' (array) and 'weights.ua_suspicious' (int).
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ua = trim((string)$log->user_agent);
        $engines = $params['browser_engines'] ?? [];
        
        // Check if the User-Agent contains at least one known browser engine.
        foreach ($engines as $engine) {
            if (str_contains($ua, (string)$engine)) {
                // A valid engine found; user is likely using a real browser.
                return;
            }
        }

        // No engine found: apply penalty and flag as suspicious.
        $score = $params['score'] ?? [];
        $penalty = (int)($score ?? 50);

        $state->add(
            $penalty,
            'ua_suspicious',
            ['reason' => 'missing_browser_engine']
        );
    }
}