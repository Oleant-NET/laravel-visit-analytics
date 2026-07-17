<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Referer;

use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

/**
 * Class PortLeakRule
 * 
 * Detects suspicious traffic originating from common hosting control panel ports 
 * found within the Referer header, which often indicates automated scanning 
 * or misconfigured internal tools.
 */
class PortLeakRule implements RuleInterface
{
    /**
     * Applies the port leak detection rule.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        if (empty($log->referer)) {
            return;
        }

        $weights = $params['weights'] ?? [];
        $leakPorts = $params['port_leak'] ?? [2082, 2083, 2086, 2087, 8888, 8443];
        $penalty = (int)($weights['port_leak'] ?? 45);

        foreach ($leakPorts as $port) {
            if (str_contains($log->referer, ":$port")) {
                $state->add($penalty, 'port_leak', [
                    'leaked_port' => $port
                ]);
                
                // Once a leak is detected, we don't need to check other ports
                break;
            }
        }
    }
}