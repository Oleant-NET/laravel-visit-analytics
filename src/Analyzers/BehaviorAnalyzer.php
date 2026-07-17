<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class BehaviorAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * {@inheritdoc}
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if (!$log->ip_address) {
            return;
        }

        // The logic is now encapsulated in the base class
        $this->executeRules($log, $state, $params);
    }
}