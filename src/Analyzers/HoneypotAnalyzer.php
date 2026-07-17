<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
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
class HoneypotAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
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
       // The logic is now encapsulated in the base class
        $this->executeRules($log, $state, $params);
    }
}
