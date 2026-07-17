<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Behavioral;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBehaviorRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class SuspiciousEntryRule extends AbstractBehaviorRule
{
    /**
     * Detects suspicious navigation entry points where no previous 
     * activity exists for the IP, but the referrer indicates an internal hit.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $prev = VisitLog::query()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderByDesc('id')
            ->first();

        // Combine both conditions: no history AND referer is present
        if (!$prev && !empty($log->referer)) {
            $refererHost = parse_url($log->referer, PHP_URL_HOST);
            $currentHost = parse_url($log->url, PHP_URL_HOST);

            if ($refererHost && $refererHost === $currentHost) {
                $state->add(
                    (int)($params['weights']['suspicious_entry'] ?? 100),
                    'suspicious_entry',
                    ['referer' => $log->referer]
                );
            }
        }
    }
}