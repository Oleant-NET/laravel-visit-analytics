<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Behavioral;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBehaviorRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class HeaderSetStabilityRule extends AbstractBehaviorRule
{
    /**
     * Detects changes to the browser identity by comparing the keys of the header sets.
     * 
     * We ignore changes in header values as they are expected during navigation,
     * but the removal of existing header keys is a strong signal of proxy/bot behavior.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $window = (int)($params['header_stability_window'] ?? 30);
        $from = $this->ensureCarbon($log->created_at)->copy()->subMinutes($window);

        // Fetch the most recent visit to compare the header set
        $previousLog = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->where('created_at', '>=', $from)
            ->orderByDesc('id')
            ->first();

        if (!$previousLog) {
            return;
        }

        $prevKeys = array_keys((array) $previousLog->target_headers);
        $currKeys = array_keys((array) $log->target_headers);

        // Fetch ignored headers from config (dynamic ones that change naturally)
        $ignored = $params['exclude_dynamic_headers'] ?? [];
        
        // Identify actual loss, ignoring the pre-defined dynamic keys
        $lostHeaders = array_diff($prevKeys, $currKeys);
        $actualLoss = array_diff($lostHeaders, $ignored);

        if (!empty($actualLoss)) {
            $state->add(
                (int)($params['weights']['header_set_anomaly'] ?? 30),
                'header_set_anomaly',
                [
                    'time_diff'    => $previousLog->created_at->diffForHumans($log->created_at),
                    'lost_headers' => array_values($actualLoss),
                ]
            );
        }
    }
}