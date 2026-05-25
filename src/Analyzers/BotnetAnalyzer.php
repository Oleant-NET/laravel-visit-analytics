<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Support\Facades\Log;

/**
 * Class BotnetAnalyzer
 * * Analyzes distributed botnets by detecting fingerprint clusters
 * within the VisitLog database.
 */
class BotnetAnalyzer implements BotAnalyzerInterface
{
    /**
     * Analyze the request for cluster anomalies.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        if ($state->isOfficialBot || empty($log->fingerprint_hash)) {
            return;
        }

        $window = now()->subMinutes($params['analysis_window_minutes'] ?? 10);
        
        $clusterQuery = VisitLog::where('fingerprint_hash', $log->fingerprint_hash)
            ->where('created_at', '>=', $window);

        $isCluster = (clone $clusterQuery)->where('ip_address', '!=', $log->ip_address)->exists();

        if ($isCluster) {
            $points = (int)($params['weights']['cluster_anomaly_weight'] ?? 100);

            $now = now();
            
            $clusterQuery->update([
                'is_bot' => true,
                'bot_score' => $points, // Ставим скор всем!
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

    /**
     * Check if the User-Agent is on the whitelist.
     * * @param string|null $userAgent
     * @param array $params
     * @return bool
     */
    protected function isWhitelisted(?string $userAgent, array $params): bool
    {
        if (empty($userAgent)) {
            return true; // If no UA, skip to avoid false positives
        }

        $patterns = $params['whitelist_patterns'] ?? [];
        $whitelist = is_callable($patterns) ? $patterns() : (array) $patterns;

        foreach ($whitelist as $pattern) {
            if (!empty($pattern) && stripos($userAgent, $pattern) !== false) {
                return false; // Should not analyze
            }
        }

        return true;
    }
}