<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractHeaderIntegrityRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class HeaderCookieRule
 * 
 * Manages evidence collection regarding cookie headers.
 */
class HeaderCookieRule extends AbstractHeaderIntegrityRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $headers = $log->target_headers ?? [];

        if ($this->isHeaderTracked('cookie', $params) && !isset($headers['cookie'])) {
            $state->addEvidence('cookie_missing_in_headers', true);
        }
    }
}