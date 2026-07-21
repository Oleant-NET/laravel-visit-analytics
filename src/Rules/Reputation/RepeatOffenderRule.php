<?php

namespace Oleant\VisitAnalytics\Rules\Reputation;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class RepeatOffenderRule implements RuleInterface
{
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $hours = (int)($params['history_window_hours'] ?? 24);
        
        $pastOffenses = VisitLog::where('ip_address', $log->ip_address)
            ->where('is_bot', true)
            ->where('created_at', '>=', now()->subHours($hours))
            ->where('id', '<', $log->id)
            ->count();

        if ($pastOffenses > 0) {
            $multiplier = (int)($params['score'] ?? 10);
            $state->add($pastOffenses * $multiplier, 'repeat_offender', [
                'past_offenses_count' => $pastOffenses,
                'history_window' => "{$hours}h"
            ]);
        }
    }
}