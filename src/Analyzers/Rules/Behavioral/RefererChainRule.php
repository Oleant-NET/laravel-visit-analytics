<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Behavioral;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBehaviorRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class RefererChainRule extends AbstractBehaviorRule
{
    /**
     * Validates navigation flow when the referer is missing.
     * Distinguishes between legitimate direct navigation, refreshes,
     * and potential crawler behavior.
     *
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

        // 1. Identify Direct Navigation (e.g., bookmark, direct URL entry)
        if ($this->header($log, 'sec-fetch-site') === 'none') {
            $state->addEvidence('referer_source', 'direct_navigation');
            return;
        }

        // 2. Identify Page Refresh
        if ($prev && $prev->url === $log->url) {
            $state->addEvidence('nav_type', 'page_refresh');
            return;
        }

        // 3. Flag Broken Referer Chain
        // If it's not a refresh and not a direct entry, a missing referer 
        // during internal navigation is suspicious.
        $penalty = (int)($params['cumulative']['no_referer_increment'] ?? 5);
        
        $state->add(
            $penalty,
            'broken_referer_chain',
            ['prev_page' => $prev->url ?? 'unknown']
        );
    }
}