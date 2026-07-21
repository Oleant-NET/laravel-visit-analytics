<?php

namespace Oleant\VisitAnalytics\Rules\Behavioral;

use Oleant\VisitAnalytics\Traits\BehaviorAnalysis;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class VisitDepthRule
 * 
 * Identifies "single hit" scanners that have no other activity
 * within the defined time window.
 */
class VisitDepthRule implements RuleInterface
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
        // Skip analysis for AJAX requests and traffic coming from referrers
        if ($this->isAjaxRequest($log) || !empty($log->referer)) {
            return;
        }

        // Define the time window for activity scanning
        $window = (int)($params['depth_check_window'] ?? 60);
        $baseTime = $this->ensureCarbon($log->created_at);

        // Check if there are any other visits from this IP within the window
        $otherVisitsCount = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '!=', $log->id)
            ->whereBetween('created_at', [
                $baseTime->copy()->subMinutes($window),
                $baseTime->copy()->addMinutes($window)
            ])
            ->count();

        // If no other visits found, mark as a "single page scan"
        if ($otherVisitsCount === 0) {
            $state->add(
                (int)($params['score'] ?? 5),
                'single_page_scan',
                ['visit_depth' => '1_page_only']
            );
        }
    }
}