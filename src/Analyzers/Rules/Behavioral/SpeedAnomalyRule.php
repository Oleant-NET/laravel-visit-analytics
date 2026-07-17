<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Behavioral;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBehaviorRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class SpeedAnomalyRule extends AbstractBehaviorRule
{
    /**
     * Detects rapid navigation patterns that indicate non-human activity.
     * 
     * Ignores AJAX/SPA traffic to prevent false positives from background requests.
     * Requires sequential "fast" hits to confirm an anomaly.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        // Fetch the previous visit for the current IP
        $prev = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderByDesc('id')
            ->first();

        // Skip if no previous history or if either request is an AJAX/SPA call
        if (!$prev || $this->isAjaxRequest($log) || $this->isAjaxRequest($prev)) {
            return;
        }

        // Calculate time interval in milliseconds
        $diffMs = abs(
            $this->ensureCarbon($log->created_at)
                ->diffInMilliseconds($this->ensureCarbon($prev->created_at))
        );

        $state->addEvidence('request_interval_ms', $diffMs);

        // Apply penalty if the interval is below the defined threshold
        $minIntervalMs = (int)($params['min_interval_ms'] ?? 250);

        if ($diffMs < $minIntervalMs) {
            // Confirm previous hit was also flagged for speed issues to ensure pattern consistency
            $wasPrevFast = is_array($prev->bot_reasons) && in_array(
                'speed_anomaly',
                $prev->bot_reasons,
                true
            );

            if ($wasPrevFast) {
                $state->add(
                    (int)($params['weights']['speed_anomaly'] ?? 10),
                    'speed_anomaly'
                );
            }
        }
    }
}