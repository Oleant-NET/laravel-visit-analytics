<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Class RetroAnalysisService
 *
 * Performs background analysis of anonymized traffic patterns.
 * Optimized to handle batch-like updates while ensuring JSON integrity 
 * across different database drivers (especially SQLite).
 */
class RetroAnalysisService
{
    /** @var int The "Golden Window" in seconds for session grouping */
    protected int $sessionWindow;

    /** @var int Max requests allowed in the session window */
    protected int $burstThreshold;

    /** @var int How many minutes back to look for logs */
    protected int $lookbackMinutes;

    public function __construct()
    {
        $retroConfig = config('visit-analytics-retroactive', []);
        $retention = (int) config('visit-analytics-collection.anonymization.retention_minutes', 30);

        $this->sessionWindow   = (int)($retroConfig['session_window'] ?? 60);
        $this->burstThreshold  = (int)($retroConfig['burst_threshold'] ?? 15);
        
        $lookback = (int)($retroConfig['lookback_minutes'] ?? 15);

        if ($lookback > $retention) {
            Log::warning("VisitAnalytics: lookback_minutes ({$lookback}) exceeds retention_minutes ({$retention}). Capping to {$retention}.");
            $this->lookbackMinutes = $retention;
        } else {
            $this->lookbackMinutes = $lookback;
        }
    }

    /**
     * Executes the retroactive analysis workflow.
     * 
     * @return int Total number of logs updated as bots.
     */
    public function handle(): int
    {
        try {
            return $this->processBursts() + $this->backfillConfirmedBots();
        } catch (\Throwable $e) {
            Log::error("RetroAnalysisService failed: " . $e->getMessage(), [
                'exception' => $e
            ]);
            return 0;
        }
    }

    /**
     * Identifies anonymized IP + UA pairs that exceeded density thresholds.
     */
    protected function processBursts(): int
    {
        $suspiciousActors = VisitLog::query()
            ->select('ip_address', 'user_agent', DB::raw('COUNT(*) as request_count'))
            ->where('created_at', '>=', now()->subMinutes($this->lookbackMinutes))
            ->where('is_bot', false)
            ->groupBy('ip_address', 'user_agent')
            ->having('request_count', '>=', $this->burstThreshold)
            ->get();

        $totalAffected = 0;
        foreach ($suspiciousActors as $actor) {
            $logs = VisitLog::where('ip_address', $actor->ip_address)
                ->where('user_agent', $actor->user_agent)
                ->where('created_at', '>=', now()->subMinutes($this->lookbackMinutes))
                ->get();

            foreach ($logs as $log) {
                if ($this->applyBotStatus($log, 'burst_density_exceeded', [
                    'retro_burst' => [
                        'count' => $actor->request_count,
                        'threshold' => $this->burstThreshold,
                        'analyzed_at' => now()->toDateTimeString()
                    ]
                ])) {
                    $totalAffected++;
                }
            }
        }
        return $totalAffected;
    }

    /**
     * Backfills preceding requests for already flagged bot IPs within the session window.
     */
    protected function backfillConfirmedBots(): int
    {
        $flaggedData = VisitLog::select('ip_address', DB::raw('MIN(created_at) as earliest_bot_hit'))
            ->where('is_bot', true)
            ->where('processed_at', '>=', now()->subMinutes($this->lookbackMinutes))
            ->groupBy('ip_address')
            ->get();

        if ($flaggedData->isEmpty()) return 0;

        $flaggedIps = $flaggedData->pluck('ip_address')->toArray();
        $minCreatedAt = $flaggedData->min('earliest_bot_hit');

        $logsToBackfill = VisitLog::whereIn('ip_address', $flaggedIps)
            ->where('is_bot', false)
            ->where('created_at', '>=', \Carbon\Carbon::parse($minCreatedAt)->subSeconds($this->sessionWindow))
            ->get();

        $affected = 0;
        foreach ($logsToBackfill as $log) {
            if ($this->applyBotStatus($log, 'retroactive_session_backfill', [
                'retro_backfill' => [
                    'source' => 'session_correlation',
                    'session_window' => $this->sessionWindow,
                    'confirmed_at' => now()->toDateTimeString()
                ]
            ])) {
                $affected++;
            }
        }
        return $affected;
    }

    /**
     * Centralized update logic to ensure JSON data integrity.
     * This handles the "bottleneck" by ensuring we don't rely on auto-casting 
     * during raw updates, maintaining compatibility across database drivers.
     *
     * @param VisitLog $log
     * @param string $reason
     * @param array $evidence
     * @return bool
     */
    protected function applyBotStatus(VisitLog $log, string $reason, array $evidence): bool
    {
        $reasons = (array) ($log->bot_reasons ?? []);
        if (!in_array($reason, $reasons)) {
            $reasons[] = $reason;
        }

        $currentEvidence = (array) ($log->bot_evidence ?? []);
        $mergedEvidence = array_merge($currentEvidence, $evidence);

        // We use update() by ID to maintain performance, but we explicitly 
        // json_encode() arrays to guarantee SQLite consistency regardless 
        // of model $casts settings or $timestamps flag.
        return (bool) VisitLog::where('id', $log->id)->update([
            'is_bot'       => true,
            'bot_score'    => max($log->bot_score ?? 0, 100),
            'bot_reasons'  => json_encode($reasons),
            'bot_evidence' => json_encode($mergedEvidence),
            'processed_at' => $log->processed_at ?? now(),
        ]);
    }
}