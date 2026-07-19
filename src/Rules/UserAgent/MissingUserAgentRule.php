<?php

namespace Oleant\VisitAnalytics\Rules\UserAgent;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class MissingUserAgentRule
 * 
 * Validates the presence of the User-Agent header in the visit log.
 * A missing or empty User-Agent is a classic signature of basic automated 
 * bots and scripts, warranting an immediate anomaly flag.
 */
class MissingUserAgentRule implements RuleInterface
{
    /**
     * Applies the rule to the provided visit log.
     *
     * @param VisitLog $log The current visit log model.
     * @param AnalysisState $state The state object for accumulating results.
     * @param array $params Package configuration, specifically looking for 'weights.missing_ua'.
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ua = trim((string)$log->user_agent);

        // If the User-Agent is present, we consider this rule passed.
        if (!empty($ua)) {
            return;
        }

        $score = (int)($params['score'] ?? 100);

        // Flag the anomaly in the analysis state.
        $state->add(
            $score,
            'missing_user_agent',
            ['ua_status' => 'empty_header']
        );
    }
}