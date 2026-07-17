<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class RefererAnalyzer
 * 
 * Analyzes Referer header integrity to detect direct navigation anomalies,
 * port leakage, and impossible self-referencing navigation loops.
 * Delegates rule execution to the AbstractAnalyzer base class.
 */
class RefererAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * Executes the referer analysis pipeline.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params Package configuration and rule parameters.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $this->executeRules($log, $state, $params);
    }
}