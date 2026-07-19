<?php

namespace Oleant\VisitAnalytics\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Traits\HeaderAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderConsistencyRule
 * 
 * Analyzes consistency between User-Agent, Client Hints, and architectural metadata.
 */
class HeaderConsistencyRule implements RuleInterface
{
    use HeaderAnalysis;

    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $headers = $log->target_headers ?? [];
        $userAgent = (string) $log->user_agent;

        // The analyzeConsistency method is now available via HeaderAnalysis trait
        $this->analyzeConsistency($headers, $userAgent, $state, $params);
    }
}