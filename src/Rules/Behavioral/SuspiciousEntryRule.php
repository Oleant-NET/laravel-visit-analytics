<?php

namespace Oleant\VisitAnalytics\Rules\Behavioral;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class SuspiciousEntryRule
 * 
 * Detects suspicious navigation entry points where no previous 
 * activity exists for the IP, but the referrer indicates an internal hit.
 */
class SuspiciousEntryRule implements RuleInterface
{
    /**
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
                    (int)($params['score'] ?? 100),
                    'suspicious_entry',
                    ['referer' => $log->referer]
                );
            }
        }
    }
}