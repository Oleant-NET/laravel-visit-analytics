<?php

namespace Oleant\VisitAnalytics\Contracts;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Interface RuleInterface
 *
 * Defines the contract for modular behavioral analysis rules.
 * Each rule represents a discrete unit of logic used to evaluate visitor behavior.
 */
interface RuleInterface
{
    /**
     * Apply the rule logic to a specific visit log entry.
     *
     * @param VisitLog $log The visit log instance being analyzed.
     * @param AnalysisState $state The mutable state object to record anomalies, scores, and evidence.
     * @param array $params Configuration parameters and thresholds relevant to the rule execution.
     * 
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void;
}