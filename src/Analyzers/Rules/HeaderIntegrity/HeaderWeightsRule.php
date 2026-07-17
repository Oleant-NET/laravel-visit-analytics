<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractHeaderIntegrityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderWeightsRule
 * 
 * Evaluates the presence of mandatory headers and applies threat scores.
 */
class HeaderWeightsRule extends AbstractHeaderIntegrityRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $this->evaluateHeaderWeights(
            $log->target_headers ?? [],
            (string) $log->user_agent,
            $state,
            $params['weights'] ?? []
        );
    }
}