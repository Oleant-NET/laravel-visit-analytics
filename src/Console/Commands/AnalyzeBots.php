<?php

namespace Oleant\VisitAnalytics\Console\Commands;

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\BotAnalysisService;
use Oleant\VisitAnalytics\Services\RetroAnalysisService;
use Oleant\VisitAnalytics\Services\BotnetService;
use Illuminate\Console\Command;

/**
 * Class AnalyzeBots
 * * Orchestrates the bot detection process by combining real-time behavioral 
 * analysis with retroactive pattern recognition and botnet cluster detection.
 */
class AnalyzeBots extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'visit-analytics:analyze-bots 
                            {--max=1000 : Maximum records to process} 
                            {--full : Display detailed report and progress}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Analyze visit logs to detect and flag bot activity';

    /**
     * Behavioral analysis configuration.
     * * @var array<string, mixed>
     */
    protected array $config = [];

    /**
     * AnalyzeBots constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->config = config('visit-analytics.behavioral_analysis', []);
    }

    /**
     * Execute the console command.
     *
     * @param BotAnalysisService $service
     * @param RetroAnalysisService $retroService
     * @param BotnetService $botnetService
     * @return int
     */
    public function handle(
        BotAnalysisService $service, 
        RetroAnalysisService $retroService, 
        BotnetService $botnetService
    ): int {
        $maxTotal = (int) $this->option('max');
        $isFull = (bool) $this->option('full');
        $threshold = (int) ($this->config['threshold'] ?? 70);

        $processedCount = 0;
        $botsDetected = 0;
        $retroactiveHits = 0;
        $newBotnetsDetected = 0;

        if ($isFull) {
            $this->printStartupInfo($maxTotal, $threshold);
        }

        // 1. Primary Analysis: Process unprocessed logs in chunks
        VisitLog::whereNull('processed_at')
            ->orderBy('id', 'asc')
            ->chunkById(100, function ($logs) use ($service, &$processedCount, &$botsDetected, $maxTotal, $isFull) {
                $startTime = microtime(true);
                $newLookups = 0;

                foreach ($logs as $log) {
                    if ($processedCount >= $maxTotal) {
                        return false;
                    }

                    // Perform behavioral analysis using the DTO-based service
                    $result = $service->analyze($log);

                    if ($result->isBot) {
                        $botsDetected++;
                    }

                    $ip = app(\Oleant\VisitAnalytics\Services\IpAnonymizerService::class)->handle(
                        $log->ip_address, 
                        $result->isBot, 
                        final: true
                    );

                    $log->update([
                        'ip_address'      => $ip,
                        'bot_score'       => min($result->score, 100),
                        'is_bot'          => $result->isBot,
                        'is_official_bot' => $result->isOfficialBot,
                        'bot_reasons'     => $result->reasons,
                        'bot_evidence'    => array_merge($result->evidence, [
                            'analyzed_at' => now()->toDateTimeString()
                        ]),
                        'processed_at'    => now(),
                    ]);

                    $processedCount++;
                    $newLookups += $result->newLookups;

                    if ($isFull) {
                        $this->output->write('.');
                    }
                }

                if ($isFull) {
                    $this->printChunkSummary($startTime, $newLookups, $processedCount);
                }

                return true;
            });

        // 2. Retroactive & Botnet Analysis: Perform cleanup and cluster detection
        if ($processedCount > 0) {
            if ($isFull) {
                $this->newLine();
                $this->info("Starting retroactive and botnet cluster analysis...");
            }
            
            // Standard retroactive cleanup
            $retroactiveHits = $retroService->handle();

            // Detect distributed botnet clusters based on UA/IP patterns
            $newBotnetsDetected = $botnetService->detectNewClusters();
        }

        // 3. Final Reporting
        $this->reportResults($processedCount, $botsDetected, $retroactiveHits, $newBotnetsDetected, $isFull);

        return self::SUCCESS;
    }

    /**
     * Display or log analysis results.
     * * @param int $processed
     * @param int $bots
     * @param int $retroactive
     * @param int $newBotnets
     * @param bool $isFull
     * @return void
     */
    protected function reportResults(int $processed, int $bots, int $retroactive, int $newBotnets, bool $isFull): void
    {
        $rate = $processed > 0 ? round(($bots / $processed) * 100, 2) : 0;
        $timestamp = now()->format('Y-m-d H:i:s');

        if ($isFull) {
            $this->newLine();
            $this->info("Analysis finished at " . $timestamp);
            $this->table(['Metric', 'Value'], [
                ['Total Processed', $processed],
                ['Bots Detected', $bots],
                ['Detection Rate', $rate . '%'],
                ['Retroactive Hits', $retroactive],
                ['New Botnet Clusters', $newBotnets],
            ]);
        } else {
            $this->line(sprintf(
                "[%s] OK: %d | Bots: %d (%s%%) | Retro: %d | New Botnets: %d",
                $timestamp, $processed, $bots, $rate, $retroactive, $newBotnets
            ));
        }
    }

    /**
     * Print startup configuration info.
     * * @param int $max
     * @param int $threshold
     * @return void
     */
    protected function printStartupInfo(int $max, int $threshold): void
    {
        $this->info("Starting analysis at " . now()->format('H:i:s'));
        $this->info("Limit: {$max} records. Threshold: {$threshold} points.");
    }

    /**
     * Print progress summary for each chunk.
     * * @param float $startTime
     * @param int $newLookups
     * @param int $totalProcessed
     * @return void
     */
    protected function printChunkSummary(float $startTime, int $newLookups, int $totalProcessed): void
    {
        $time = round(microtime(true) - $startTime, 2);
        $this->newLine();
        $this->info("Chunk processed: {$time}s | New DNS Lookups: {$newLookups} | Total: {$totalProcessed}");
    }
}