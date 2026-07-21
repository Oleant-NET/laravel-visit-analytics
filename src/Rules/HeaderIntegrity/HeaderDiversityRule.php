<?php

namespace Oleant\VisitAnalytics\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Traits\HeaderAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderDiversityRule
 * 
 * Validates that the request contains a sufficient number of headers.
 */
class HeaderDiversityRule implements RuleInterface
{
    use HeaderAnalysis;

    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $headers = $log->target_headers ?? [];
        
        $this->evaluateHeaderDiversity($headers, $state, $params);
    }
}