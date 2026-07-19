<?php

namespace Oleant\VisitAnalytics\Rules\ObsoleteOS;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class ObsoleteBrowserRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ua = (string) $log->user_agent;
        $patterns = $params['target_browsers'] ?? [];
        $weight = (int) ($params['score'] ?? 35);

        foreach ($patterns as $pattern) {
            if (!empty($pattern) && stripos($ua, $pattern) !== false) {
                $state->add($weight, 'obsolete_browsers', [
                    'browsers_signature' => $pattern
                ]);
                break;
            }
        }
    }
}