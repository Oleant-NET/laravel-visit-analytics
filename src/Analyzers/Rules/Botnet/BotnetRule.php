<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Botnet;

use Oleant\VisitAnalytics\Analyzers\Rules\Base\AbstractBotnetRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

class BotnetRule extends AbstractBotnetRule
{
    /**
     * Identifies "botnet" scanners that have no other activity
     * within the defined time window.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function apply(VisitLog $log, AnalysisState $state, array $params): void
    {
        $window = now()->subMinutes($params['analysis_window_minutes'] ?? 10);
        
        $clusterQuery = VisitLog::where('fingerprint_hash', $log->fingerprint_hash)
            ->where('created_at', '>=', $window);

        $uniqueIpCount = (clone $clusterQuery)
            ->where('ip_address', '!=', $log->ip_address)
            ->distinct('ip_address')
            ->count('ip_address');

        if ($uniqueIpCount >= $params['ip_cluster_threshold']) {
            $points = (int)($params['weights']['cluster_anomaly_weight'] ?? 100);

            $now = now();
            
            $clusterQuery->update([
                'is_bot' => true,
                'bot_score' => $points,
                'bot_reasons' => json_encode(['botnet_cluster_match']),
                'bot_evidence' => json_encode(['analyzed_at' => $now->toDateTimeString(), 'signature' => 'cluster_anomaly']),
                'processed_at' => $now
            ]);

            $state->add($points, 'botnet_cluster_match', [
                'signature' => 'cluster_anomaly',
                'status' => 'cluster_marked_as_bot'
            ]);
        }
    }
}