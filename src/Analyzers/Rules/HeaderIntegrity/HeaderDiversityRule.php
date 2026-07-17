<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractHeaderIntegrityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderDiversityRule
 * 
 * Validates that the request contains a sufficient number of headers.
 */
class HeaderDiversityRule extends AbstractHeaderIntegrityRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $headers = $log->target_headers ?? [];
        
        // Evaluate the total number of headers against the defined threshold
        $this->evaluateHeaderDiversity($headers, $state, $params['min_total_headers'] ?? []);
    }
}