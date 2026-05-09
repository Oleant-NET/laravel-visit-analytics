<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\DB;

/**
 * Class RetroAnalysisService
 *
 * background analysis of anonymized traffic patterns.
 * Optimized with pre-loaded configuration and batch updates.
 */
class RetroAnalysisService
{
    /** @var int The "Golden Window" in seconds for session grouping */
    protected int $sessionWindow;

    /** @var int Max requests allowed in the session window */
    protected int $burstThreshold;

    /** @var int How many minutes back to look for logs */
    protected int $lookbackMinutes;

    /**
     * RetroAnalysisService constructor.
     * Pre-loads configuration to avoid repeated config() calls.
     */
    public function __construct()
    {
        $config = config('visit-analytics.retro_analysis', []);
        
        $this->sessionWindow   = (int)($config['session_window'] ?? 60);
        $this->burstThreshold  = (int)($config['burst_threshold'] ?? 15);
        $this->lookbackMinutes = (int)($config['lookback_minutes'] ?? 15);
    }

    /**
     * Executes the retroactive analysis workflow.
     * Uses a try-catch block to ensure cron stability.
     */
    public function handle(): int
    {
        $updated = 0;

        try {
            // 1. Detect rapid request bursts (Density analysis)
            $updated += $this->processBursts();

            // 2. Backfill confirmed bot hits (Session cleanup)
            $updated += $this->backfillConfirmedBots();

        } catch (\Throwable $e) {
            \Log::error("RetroAnalysisService failed: " . $e->getMessage(), [
                'exception' => $e,
                'trace' => $e->getTraceAsString(),
            ]);
        }

        return $updated;
    }

    /**
     * Identifies anonymized IP + UA pairs that exceeded density thresholds.
     */
    protected function processBursts(): int
    {
        $suspiciousActors = VisitLog::query()
            ->select('ip_address', 'user_agent', DB::raw('COUNT(*) as request_count'))
            ->where('created_at', '>=', now()->subMinutes($this->lookbackMinutes)) // Фикс: смотрим по created_at
            ->where('is_bot', false)
            ->groupBy('ip_address', 'user_agent')
            ->having('request_count', '>=', $this->burstThreshold)
            ->get();

        if ($suspiciousActors->isEmpty()) {
            return 0;
        }

        $totalAffected = 0;

        foreach ($suspiciousActors as $actor) {
            // Находим все логи этого актора за период
            $logs = VisitLog::query()
                ->where('ip_address', $actor->ip_address)
                ->where('user_agent', $actor->user_agent)
                ->where('created_at', '>=', now()->subMinutes($this->lookbackMinutes))
                ->get();

            foreach ($logs as $log) {
                // --- ЛОГИКА СКЛЕЙКИ ---
                $currentReasons = $log->bot_reasons ?? [];
                if (!in_array('burst_density_exceeded', $currentReasons)) {
                    $currentReasons[] = 'burst_density_exceeded';
                }

                $currentEvidence = $log->bot_evidence ?? [];
                $currentEvidence['retro_burst'] = [
                    'count' => $actor->request_count,
                    'threshold' => $this->burstThreshold,
                    'analyzed_at' => now()->toDateTimeString()
                ];

                $log->update([
                    'is_bot'       => true,
                    'bot_score'    => max($log->bot_score ?? 0, 100), // Не занижаем, если уже было 100
                    'bot_reasons'  => $currentReasons,
                    'bot_evidence' => $currentEvidence,
                    'processed_at' => $log->processed_at ?? now(), // Сохраняем старый таймстамп, если есть
                ]);
                
                $totalAffected++;
            }
        }

        return $totalAffected;
    }

    /**
     * Backfills preceding requests for already flagged bot IPs within the session window.
     * * This method complements primary analysis by flagging early "quiet" hits 
     * without overwriting existing reasons or evidence.
     */
    protected function backfillConfirmedBots(): int
    {
        // 1. Get unique masked IPs that were flagged as bots in the lookback period
        // Добавляем получение минимального времени создания, чтобы окно не "уплыло"
        $flaggedData = VisitLog::query()
            ->select('ip_address', DB::raw('MIN(created_at) as earliest_bot_hit'))
            ->where('is_bot', true)
            ->where('processed_at', '>=', now()->subMinutes($this->lookbackMinutes))
            ->groupBy('ip_address')
            ->get();

        if ($flaggedData->isEmpty()) {
            return 0;
        }

        $flaggedIps = $flaggedData->pluck('ip_address')->toArray();
        // Берем самое раннее время среди всех найденных ботов для корректного окна
        $minCreatedAt = $flaggedData->min('earliest_bot_hit');

        $affected = 0;
        $backfillReason = 'retroactive_session_backfill';

        // 2. Find all "clean" records for these IPs within the tight session window (60s)
        // Фикс: привязываемся к времени логов ($minCreatedAt), а не к текущему времени (now)
        $logsToBackfill = VisitLog::query()
            ->whereIn('ip_address', $flaggedIps)
            ->where('is_bot', false)
            ->where('created_at', '>=', \Carbon\Carbon::parse($minCreatedAt)->subSeconds($this->sessionWindow))
            ->where('created_at', '<=', now()) // На всякий случай ограничиваем сверху
            ->get();

        foreach ($logsToBackfill as $log) {
            // --- SAFE MERGE REASONS ---
            $reasons = $log->bot_reasons ?? [];
            if (!in_array($backfillReason, $reasons)) {
                $reasons[] = $backfillReason;
            }

            // --- SAFE MERGE EVIDENCE ---
            $evidence = $log->bot_evidence ?? [];
            $evidence['retro_backfill'] = [
                'source' => 'session_correlation',
                'session_window' => $this->sessionWindow,
                'confirmed_at' => now()->toDateTimeString()
            ];

            // --- UPDATE WITHOUT OVERWRITING ---
            $log->update([
                'is_bot'       => true,
                // Use max() to ensure we never lower a score if it was already high
                'bot_score'    => max($log->bot_score ?? 0, 100),
                'bot_reasons'  => $reasons,
                'bot_evidence' => $evidence,
                // Keep original processed_at if it exists, otherwise set now
                'processed_at' => $log->processed_at ?? now(),
            ]);

            $affected++;
        }

        return $affected;
    }
}