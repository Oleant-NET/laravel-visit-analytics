<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class ReputationAnalyzer
 * 
 * Analyzes the historical reputation of an IP address.
 * Penalties are applied if the IP has been flagged as a bot in the recent past.
 */
class ReputationAnalyzer implements BotAnalyzerInterface
{
    /**
     * Checks if the IP address has a history of bot detections.
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $cumulativeConfig = $params['cumulative'] ?? [];

        // 1. Check if cumulative analysis is enabled
        if (!($cumulativeConfig['enabled'] ?? false)) {
            return;
        }

        if (!$log->ip_address) {
            return;
        }

        $hours = (int)($cumulativeConfig['history_window_hours'] ?? 24);
        
        // 2. Count previous bot detections for this IP within the time window
        $pastOffenses = VisitLog::where('ip_address', $log->ip_address)
            ->where('is_bot', true)
            ->where('created_at', '>=', now()->subHours($hours))
            ->where('id', '<', $log->id)
            ->count();

        if ($pastOffenses > 0) {
            $multiplier = (int)($cumulativeConfig['penalty_multiplier'] ?? 10);
            $totalPenalty = $pastOffenses * $multiplier;

            // 3. Add penalty and evidence
            $state->add($totalPenalty, 'repeat_offender', [
                'past_offenses_count' => $pastOffenses,
                'history_window' => "{$hours}h"
            ]);
        }
    }
}
