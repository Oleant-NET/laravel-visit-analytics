<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class OutdatedBrowserAnalyzer
 * 
 * Analyzes the browser version to detect legacy software or automation tools.
 * It delegates evaluation to registered rules like OutdatedBrowserRule.
 */
class OutdatedBrowserAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    /**
     * Executes the browser version check against configured thresholds using rules.
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

        // The logic is now encapsulated in the base class and rule execution
        $this->executeRules($log, $state, $params);
    }
}