<?php

namespace Oleant\VisitAnalytics\Rules\Referer;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Traits\QueriesVisitHistory;

class MissingRefererRule implements RuleInterface
{
    use QueriesVisitHistory;

    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        if (!empty($log->referer)) return;

        $score = $params['score'] ?? [];
        $config = $params['cumulative'] ?? [];
        $fetchSite = $log->target_headers['sec-fetch-site'] ?? null;
        $window = (int)($config['no_referer_window_minutes'] ?? 10);

        // 1. Penalty logic
        if ($fetchSite !== null && ($fetchSite === 'same-origin' || $fetchSite === 'cross-site')) {
            if ($this->isInitialDirectHit($log, $window)) return;

            $state->add((int)($score ?? 35), 'missing_referer_on_navigation', [
                'sec_fetch_site' => $fetchSite
            ]);
        } elseif ($fetchSite === null) {
            $state->add((int)($score ?? 35), 'missing_referer');
        }

        // 2. Snowball logic
        if ($fetchSite === 'none' || $fetchSite === null) {
            $count = $this->getSequentialDirectHitsCount($log, $window);
            if ($count > 0) {
                $multiplier = (int)($config['no_referer_increment'] ?? 20);
                $state->add($count * $multiplier, 'referer_snowball', ['sequential_direct_hits' => $count]);
            }
        }
    }
}