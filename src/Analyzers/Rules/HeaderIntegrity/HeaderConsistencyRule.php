<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractHeaderIntegrityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderConsistencyRule
 * 
 * Analyzes consistency between User-Agent, Client Hints, and architectural metadata.
 */
class HeaderConsistencyRule extends AbstractHeaderIntegrityRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $headers = $log->target_headers ?? [];
        $userAgent = (string) $log->user_agent;

        // Run deep inspection of header consistency
        $this->analyzeConsistency($headers, $userAgent, $state, $params['consistency_checks'] ?? []);
    }
}