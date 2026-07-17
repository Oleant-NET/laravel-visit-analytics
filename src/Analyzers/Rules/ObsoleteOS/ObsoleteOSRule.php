<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\ObsoleteOS;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class ObsoleteOSRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ua = (string) $log->user_agent;
        $patterns = $params['target_os'] ?? [];
        $weight = (int) ($params['weights']['obsolete_os'] ?? 35);

        foreach ($patterns as $pattern) {
            if (!empty($pattern) && stripos($ua, $pattern) !== false) {
                $state->add($weight, 'obsolete_os', [
                    'os_signature' => $pattern
                ]);
                break;
            }
        }
    }
}