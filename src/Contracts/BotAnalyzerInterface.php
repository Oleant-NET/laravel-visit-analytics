<?php

namespace Oleant\VisitAnalytics\Contracts;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Interface BotAnalyzerInterface
 * * Defines the contract for all bot detection modules.
 */
interface BotAnalyzerInterface
{
    /**
     * Run the analysis logic against a specific visit log.
     *
     * @param VisitLog $log The log entry instance to evaluate.
     * @param AnalysisState $state The mutable state holding cumulative scores and evidence.
     * @param array $params Localized configuration parameters for this specific analyzer.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void;
}