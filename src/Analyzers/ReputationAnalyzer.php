<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class ReputationAnalyzer
 * 
 * Analyzes the historical reputation of an IP address.
 */
class ReputationAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $this->executeRules($log, $state, $params);
    }
}