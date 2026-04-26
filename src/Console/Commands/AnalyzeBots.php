<?php

namespace Oleant\VisitAnalytics\Console\Commands;

use Oleant\VisitAnalytics\Models\VisitLog;
use Carbon\Carbon;
use Illuminate\Console\Command;

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
     * Cache for DNS lookups to avoid redundant network calls during a single run.
     *
     * @var array
     */
    protected static array $dnsCache = [];

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $config = config('visit-analytics.behavioral_analysis');
        $maxTotal = (int) $this->option('max');
        $isFull = $this->option('full');
        $threshold = (int) ($config['threshold'] ?? 70);
        
        $processedCount = 0;
        $botsDetected = 0;

        if ($isFull) {
            $this->printStartupInfo($maxTotal, $threshold);
        }

        VisitLog::whereNull('processed_at')
            ->orderBy('id', 'asc')
            ->chunkById(100, function ($logs) use (&$processedCount, &$botsDetected, $maxTotal, $threshold, $config, $isFull) {
                $startTime = microtime(true);
                $newLookups = 0;

                foreach ($logs as $log) {
                    if ($processedCount >= $maxTotal) return false;

                    // Calculate bot score using separated logic
                    $score = $this->calculateBotScore($log, $config, $newLookups);
                    
                    $isBot = $score >= $threshold;
                    if ($isBot) $botsDetected++;

                    $log->update([
                        'bot_score'    => min($score, 100),
                        'is_bot'       => $isBot,
                        'processed_at' => now(),
                    ]);

                    $processedCount++;
                    
                    if ($isFull) {
                        $this->output->write('.'); 
                    }
                }

                if ($isFull) {
                    $this->printChunkSummary($startTime, $newLookups, $processedCount);
                }
            });

        // Cleanup previous sessions from the same IPs identified as bots
        $updatedRows = $this->performRetroactiveCleanup();

        // Final Output
        $this->reportResults(
            $processedCount, 
            $botsDetected, 
            $updatedRows, 
            $isFull
        );
    }

    /**
     * Orchestrates the scoring process.
     */
    protected function calculateBotScore(VisitLog $log, array $config, int &$newLookups): int
    {
        $score = 0;

        // 1. Static Analysis (UA, Regex, Honeypots, Referer)
        $score += $this->checkStaticPatterns($log, $config);
        if ($score >= 100) return 100;

        // 2. Behavioral Analysis (Rate limits, Speed, History)
        $score += $this->checkBehavior($log, $config);
        if ($score >= 100) return 100;

        // 3. Network Analysis (DNS, PTR, Datacenters)
        $score += $this->checkNetwork($log, $config, $newLookups);

        return $score;
    }

    /**
     * Static checks: User-Agent strings and Honeypots.
     */
    protected function checkStaticPatterns(VisitLog $log, array $config): int
    {
        $score = 0;

        // Suspicious UA strings (stripos)
        foreach ($config['suspicious_ua'] ?? [] as $pattern) {
            if (stripos($log->user_agent, $pattern) !== false) {
                $score += (int)($config['weights']['ua'] ?? 30);
                break;
            }
        }

        // Advanced UA detection with version checking (e.g., future Chrome versions)
        foreach ($config['ua_regex_patterns'] ?? [] as $pattern => $weight) {
            if (preg_match($pattern, $log->user_agent, $matches)) {
                $score += (int)$weight;
                // Version check (e.g., Chrome > 135)
                if (isset($matches[1]) && (int)$matches[1] > 135) {
                    $score += (int)($config['weights']['future_chrome_bonus'] ?? 30);
                }
            }
        }

        // Honeypot trap
        foreach ($config['honeypot_paths'] ?? [] as $path) {
            if (str_contains($log->url, $path)) return 100;
        }

        // Referer analysis
        if (empty($log->referer)) {
            $path = parse_url($log->url, PHP_URL_PATH);
            $score += (trim($path ?? '', '/') !== '') 
                ? (int)(($config['weights']['no_referer'] ?? 10) * 2) 
                : (int)($config['weights']['no_referer'] ?? 10);
        }

        return $score;
    }

    /**
     * Behavioral checks: Activity frequency and path history.
     */
    protected function checkBehavior(VisitLog $log, array $config): int
    {
        if (!$log->ip_address) return 0;

        $score = 0;
        $window = (int)($config['time_window'] ?? 5);
        $from = Carbon::parse($log->created_at)->subMinutes($window);

        $history = VisitLog::where('ip_address', $log->ip_address)
            ->whereBetween('created_at', [$from, $log->created_at])
            ->get();

        // Rate limit check
        if ($history->count() > (($config['rate_limit_per_minute'] ?? 30) * $window)) {
            $score += (int)($config['weights']['rate'] ?? 40);
        }

        // Speed anomaly check
        $prev = VisitLog::where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderBy('id', 'desc')
            ->first();

        if ($prev && Carbon::parse($log->created_at)->diffInSeconds(Carbon::parse($prev->created_at)) < ($config['min_interval'] ?? 2)) {
            $score += (int)($config['weights']['speed_anomaly'] ?? 40);
        }

        return $score;
    }

    /**
     * Network checks: DNS, PTR records and Cloudflare/Datacenter detection.
     */
    protected function checkNetwork(VisitLog $log, array $config, int &$newLookups): int
    {
        if (!$log->ip_address) return 0;

        if (isset(static::$dnsCache[$log->ip_address])) {
            return static::$dnsCache[$log->ip_address];
        }

        $newLookups++;
        $dnsScore = (int)($config['weights']['no_dns_record'] ?? 20);
        
        // Handle IPv4 subnet logic (.0 to .1)
        $lookupIp = str_ends_with($log->ip_address, '.0') 
            ? substr($log->ip_address, 0, strrpos($log->ip_address, '.')) . '.1' 
            : $log->ip_address;

        try {
            $host = gethostbyaddr($lookupIp);
            if ($host && $host !== $lookupIp) {
                $dnsScore = 0; // Found a valid PTR record
                foreach ($config['datacenter_check']['keywords'] ?? [] as $kw) {
                    if (str_contains(strtolower($host), $kw)) {
                        $dnsScore = (int)($config['weights']['datacenter'] ?? 100);
                        break;
                    }
                }
            }
        } catch (\Exception $e) { }

        static::$dnsCache[$log->ip_address] = $dnsScore;
        return $dnsScore;
    }

    /**
     * Flag previous session visits from newly identified bot IPs.
     */
    protected function performRetroactiveCleanup(): int
    {
        $detectedIps = VisitLog::where('is_bot', true)
            ->whereBetween('processed_at', [now()->subMinutes(12), now()])
            ->distinct()
            ->pluck('ip_address');

        if ($detectedIps->isEmpty()) return 0;

        return VisitLog::whereIn('ip_address', $detectedIps)
            ->where('is_bot', false)
            ->update([
                'is_bot' => true,
                'bot_score' => 100,
                'processed_at' => now(),
            ]);
    }

    /**
     * Final report output.
     */
    protected function reportResults(int $processed, int $bots, int $retroactive, bool $isFull): void
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
            ]);
        } else {
            $this->line(sprintf(
                "[%s] OK: %d | Bots: %d (%s%%) | Retro: %d",
                $timestamp,
                $processed,
                $bots,
                $rate,
                $retroactive
            ));
        }
    }

    protected function printStartupInfo(int $max, int $threshold): void
    {
        $this->info("Starting analysis at " . now()->format('H:i:s'));
        $this->info("Limit: {$max} records. Threshold: {$threshold} points.");
    }

    protected function printChunkSummary(float $startTime, int $newLookups, int $total): void
    {
        $time = round(microtime(true) - $startTime, 2);
        $this->newLine();
        $this->info("Chunk processed: {$time}s | New DNS Lookups: {$newLookups} | Total: {$total}");
    }
}