<?php

namespace Oleant\VisitAnalytics\Rules\Behavioral;

use Oleant\VisitAnalytics\Traits\BehaviorAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

class RateLimitRule implements RuleInterface
{
    use BehaviorAnalysis;

    /**
     * Detects abnormal request bursts.
     * 
     * AJAX/widget traffic is excluded, as SPA frameworks legitimately
     * produce frequent background requests.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        if ($this->isAjaxRequest($log)) {
            return;
        }

        $window = (int)($params['time_window'] ?? 5);
        
        $from = $this->ensureCarbon($log->created_at)->copy()->subMinutes($window);

        // Count non-AJAX requests within the specified window
        $historyCount = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->whereBetween('created_at', [$from, $log->created_at])
            ->where(function ($query) {
                $query->whereNull('target_headers')
                      ->orWhereNull('target_headers->x-requested-with');
            })
            ->count();

        $maxRate = (int)($params['rate_limit_per_minute'] ?? 120) * $window;

        // Flag the anomaly if the request rate exceeds the threshold
        if ($historyCount > $maxRate) {
            $state->add(
                (int)($params['score'] ?? 15),
                'high_request_rate',
                [
                    'request_rate_metric' => "{$historyCount}/{$window}min",
                ]
            );
        }
    }
}