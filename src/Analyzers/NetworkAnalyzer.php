<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class NetworkAnalyzer
 * 
 * Performs Reverse DNS (PTR) lookups to identify Datacenters 
 * or missing network identity.
 */
class NetworkAnalyzer implements BotAnalyzerInterface
{
    /**
     * Static cache to prevent redundant DNS lookups during a single request/batch.
     */
    protected static array $dnsCache = [];

    /**
     * Entry point for network-based verification.
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        $ip = $log->ip_address;

        if (!$ip) {
            return;
        }

        // 1. Check internal static cache
        if (isset(self::$dnsCache[$ip])) {
            $this->applyCachedResult($state, self::$dnsCache[$ip]);
            return;
        }

        // 2. Perform Lookup
        $result = $this->performDnsLookup($ip, $params);

        // 3. Cache and apply
        self::$dnsCache[$ip] = $result;
        $this->applyCachedResult($state, $result);
    }

    /**
     * Executes the actual DNS lookup logic with IPv6 awareness.
     */
    protected function performDnsLookup(string $ip, array $params = []): array
    {
        $weights = $params['weights'] ?? [];
        $isIpv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        
        /**
         * IPv4 Edge case: handle network range ending in .0 by probing .1
         * This is skipped for IPv6 as it's not applicable.
         */
        $lookupIp = (!$isIpv6 && str_ends_with($ip, '.0')) 
            ? substr($ip, 0, strrpos($ip, '.')) . '.1' 
            : $ip;

        try {
            // PHP's native gethostbyaddr
            $host = @gethostbyaddr($lookupIp);
            
            // If PTR record exists and is valid
            if ($host && $host !== $lookupIp) {
                $keywords = $params['datacenter_check']['keywords'] ?? [];
                
                foreach ($keywords as $kw) {
                    if (str_contains(strtolower($host), (string)$kw)) {
                        return [
                            'score' => (int)($weights['datacenter'] ?? 100),
                            'reason' => 'datacenter_ip',
                            'evidence' => ['ptr_record_match' => $host]
                        ];
                    }
                }

                // Known host, no DC keywords found (likely Residential/ISP)
                return [
                    'score' => 0,
                    'reason' => null,
                    'evidence' => []
                ];
            }

            /**
             * No Reverse DNS record found.
             * For IPv6, we ignore this as many ISPs (like TeleData) don't provide PTR for end-users.
             * For IPv4, we still apply the penalty.
             */
            if ($isIpv6) {
                return [
                    'score' => 0,
                    'reason' => null,
                    'evidence' => ['network_status' => 'ipv6_no_ptr_ignored']
                ];
            }

            return [
                'score' => (int)($weights['no_dns_record'] ?? 50),
                'reason' => 'no_ptr_record',
                'evidence' => ['network_status' => 'no_reverse_dns']
            ];

        } catch (\Exception $e) {
            return ['score' => 0, 'reason' => 'dns_lookup_failed', 'evidence' => []];
        }
    }

    /**
     * Applies the lookup result to the state.
     */
    protected function applyCachedResult(AnalysisState $state, array $result): void
    {
        if ($result['score'] > 0 || $result['reason']) {
            $state->add($result['score'], $result['reason'] ?? 'network_check', $result['evidence'] ?? []);
        } else {
            // Keep evidence even if score is 0
            foreach ($result['evidence'] as $key => $value) {
                $state->addEvidence($key, $value);
            }
        }
    }
}