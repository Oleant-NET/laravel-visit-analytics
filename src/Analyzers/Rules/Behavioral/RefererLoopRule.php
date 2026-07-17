<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Behavioral;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBehaviorRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class RefererLoopRule extends AbstractBehaviorRule
{
    /**
     * Detects navigation loops where the page refers to itself.
     * 
     * Frequent self-referencing navigation is often a sign of 
     * scripted bot behavior or broken crawling logic.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        // Only trigger if referer equals current URL and it's not an AJAX request
        if (empty($log->referer) || $log->referer !== $log->url || $this->isAjaxRequest($log)) {
            return;
        }

        // Count how many times this specific loop occurred in the last 10 entries for this IP
        $sameUrlCount = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('url', $log->url)
            ->where('referer', $log->url)
            ->where('id', '>=', max(1, $log->id - 10))
            ->count();

        // Flag the anomaly if the loop repeats 3 or more times
        $threshold = (int)($params['referer_loop_threshold'] ?? 3);

        if ($sameUrlCount >= $threshold) {
            $state->addEvidence('loop_count', $sameUrlCount);
            $state->add(10, 'referer_loop');
        }
    }
}