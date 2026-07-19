<?php

namespace Oleant\VisitAnalytics\Rules\UserAgent;

use Oleant\VisitAnalytics\Traits\BehaviorAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class UserAgentStabilityRule
 * 
 * Detects if the User-Agent changes for the same IP within a short window.
 */
class UserAgentStabilityRule implements RuleInterface
{
    use BehaviorAnalysis;

    /**
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $window = (int)($params['ua_stability_window'] ?? 30);
        $from = $this->ensureCarbon($log->created_at)->copy()->subMinutes($window);

        // Look for any recent visit from the same IP with a different User-Agent
        $differentUA = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->where('created_at', '>=', $from)
            ->where('user_agent', '!=', $log->user_agent)
            ->orderByDesc('id')
            ->first();

        if ($differentUA) {
            $state->add(
                (int)($params['score'] ?? 40),
                'ua_change_anomaly',
                [
                    'previous_ua' => $differentUA->user_agent,
                    'current_ua'  => $log->user_agent,
                    'time_diff'   => $differentUA->created_at->diffForHumans($log->created_at),
                ]
            );
        }
    }
}