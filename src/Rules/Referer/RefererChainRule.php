<?php

namespace Oleant\VisitAnalytics\Rules\Referer;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class RefererChainRule
 * 
 * Validates navigation flow when the referer is missing.
 */
class RefererChainRule implements RuleInterface
{
    /**
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        // This rule only applies when there is no referer
        if (!empty($log->referer)) {
            return;
        }

        $prev = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderByDesc('id')
            ->first();

        // 1. Identify Direct Navigation
        if (($log->target_headers['sec-fetch-site'] ?? null) === 'none') {
            $state->addEvidence('referer_source', 'direct_navigation');
            return;
        }

        // 2. Identify Page Refresh
        if ($prev && $prev->url === $log->url) {
            $state->addEvidence('nav_type', 'page_refresh');
            return;
        }

        // 3. Flag Broken Referer Chain
        $penalty = (int)($params['score'] ?? 5);
        
        $state->add(
            $penalty,
            'broken_referer_chain',
            ['prev_page' => $prev->url ?? 'unknown']
        );
    }
}