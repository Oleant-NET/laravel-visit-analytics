<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Reputation;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class RepeatOffenderRule implements RuleInterface
{
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $config = $params['cumulative'] ?? [];
        if (!($config['enabled'] ?? false) || !$log->ip_address) return;

        $hours = (int)($config['history_window_hours'] ?? 24);
        
        $pastOffenses = VisitLog::where('ip_address', $log->ip_address)
            ->where('is_bot', true)
            ->where('created_at', '>=', now()->subHours($hours))
            ->where('id', '<', $log->id)
            ->count();

        if ($pastOffenses > 0) {
            $multiplier = (int)($config['penalty_multiplier'] ?? 10);
            $state->add($pastOffenses * $multiplier, 'repeat_offender', [
                'past_offenses_count' => $pastOffenses,
                'history_window' => "{$hours}h"
            ]);
        }
    }
}