<?php

namespace Oleant\VisitAnalytics\Rules\Network;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Traits\ResolvesHostname;

/**
 * Class NetworkDatacenterRule
 * 
 * Scans the hostname for known datacenter keywords.
 */
class NetworkDatacenterRule implements RuleInterface
{
    use ResolvesHostname;

    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ip = (string)$log->ip_address;
        $host = $this->resolveHostname($ip);;

        if (!$host) return;

        $keywords = $params['datacenter_keywords'] ?? [];

        foreach ($keywords as $kw) {
            if (str_contains(strtolower($host), (string)$kw)) {
                $state->add(
                    (int)($params['score'] ?? 100),
                    'datacenter_ip',
                    ['ptr_record_match' => $host]
                );
                break;
            }
        }
    }
}