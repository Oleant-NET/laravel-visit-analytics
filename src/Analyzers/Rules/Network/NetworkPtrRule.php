<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Network;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Class NetworkPtrRule
 * 
 * Verifies the existence of a PTR record for the visitor IP.
 */
class NetworkPtrRule implements RuleInterface
{
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $host = $state->getEvidenceValue('resolved_hostname');
        $isIpv6 = filter_var($log->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        // If PTR is missing (and not ignored IPv6)
        if (!$host && !$isIpv6) {
            $state->add(
                (int)($params['weights']['no_dns_record'] ?? 50),
                'no_ptr_record',
                ['network_status' => 'no_reverse_dns']
            );
        }
    }
}