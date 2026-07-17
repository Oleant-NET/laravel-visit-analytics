<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Analyzers\Base\AbstractAnalyzer;
use Oleant\VisitAnalytics\Traits\ResolvesHostname;
use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class NetworkAnalyzer
 * 
 * Orchestrates network-based verification by performing Reverse DNS lookups
 * and executing specific network integrity rules (e.g., Datacenter checks).
 */
class NetworkAnalyzer extends AbstractAnalyzer implements BotAnalyzerInterface
{
    use ResolvesHostname;

    /**
     * Entry point for network-based verification.
     * 
     * Performs a one-time DNS lookup for the visitor's IP and populates the 
     * AnalysisState with evidence, then triggers the configured rule chain.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params Package configuration including rules and weights.
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        // Skip analysis entirely if there is no IP to analyze
        if (empty($log->ip_address)) {
            return;
        }

        $ip = $log->ip_address;

        if ($ip) {
            // Resolve once and store as evidence for all subsequent rules
            $hostname = $this->resolveHostname($ip);
            
            $state->addEvidence('resolved_hostname', $hostname);
            $state->addEvidence('ip_address', $ip);
        }

        // Execute the chain of rules registered in the configuration
        // e.g., NetworkPtrRule, NetworkDatacenterRule
        $this->executeRules($log, $state, $params);
    }
}