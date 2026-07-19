<?php

namespace Oleant\VisitAnalytics\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Traits\HeaderAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderWeightsRule
 * 
 * Evaluates the presence of mandatory headers and applies threat scores.
 */
class HeaderWeightsRule implements RuleInterface
{
    use HeaderAnalysis;

    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $this->evaluateHeaderWeights(
            $log->target_headers ?? [],
            (string) $log->user_agent,
            $state,
            $params['scores_without'] ?? []
        );
    }
}