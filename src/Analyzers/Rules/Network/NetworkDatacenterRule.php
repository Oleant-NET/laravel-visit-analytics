<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Network;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class NetworkDatacenterRule
 * 
 * Scans the hostname for known datacenter keywords.
 */
class NetworkDatacenterRule implements RuleInterface
{
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $host = $state->getEvidenceValue('resolved_hostname');
        if (!$host) return;

        $keywords = $params['datacenter_check']['keywords'] ?? [];
        
        foreach ($keywords as $kw) {
            if (str_contains(strtolower($host), (string)$kw)) {
                $state->add(
                    (int)($params['weights']['datacenter'] ?? 100),
                    'datacenter_ip',
                    ['ptr_record_match' => $host]
                );
                break;
            }
        }
    }
}