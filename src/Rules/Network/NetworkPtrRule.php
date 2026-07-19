<?php

namespace Oleant\VisitAnalytics\Rules\Network;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Traits\ResolvesHostname;

/**
 * Class NetworkPtrRule
 * 
 * Verifies the existence of a PTR record for the visitor IP.
 */
class NetworkPtrRule implements RuleInterface
{
    use ResolvesHostname;    

    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $ip = (string)$log->ip_address;
        $host = $this->resolveHostname($ip);;
        $isIpv6 = filter_var($log->ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        // If PTR is missing (and not ignored IPv6)
        if (!$host && !$isIpv6) {
            $state->add(
                (int)($params['score'] ?? 50),
                'no_ptr_record',
                ['network_status' => 'no_reverse_dns']
            );
        }
    }
}