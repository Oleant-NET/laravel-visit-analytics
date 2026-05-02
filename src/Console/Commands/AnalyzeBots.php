<?php

namespace Oleant\VisitAnalytics\Console\Commands;

use Oleant\VisitAnalytics\Models\VisitLog;
use Carbon\Carbon;
use Illuminate\Console\Command;
use Exception;

/**
 * Class AnalyzeBots
 * 
 * Processes visit logs to identify automated traffic (bots) based on 
 * static patterns, behavioral anomalies, and network reputation.
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
     * Is Googlebot, bingbot, etc.
     *
     * @var boolean
     */
    protected bool $isOfficialBot = false;

    /**
     * Cache for DNS lookups to avoid redundant network calls.
     *
     * @var array<string, array{score: int, reason: string|null, host: string|null}>
     */
    protected static array $dnsCache = [];

    /**
     * List of reason slugs for the current log.
     *
     * @var string[]
     */
    protected array $currentReasons = [];

    /**
     * Detailed evidence collection for the current log.
     *
     * @var array<string, mixed>
     */
    protected array $currentEvidence = [];

    /**
     * List of IP addresses identified as bots during the current execution.
     *
     * @var string[]
     */
    protected array $detectedIps = [];

    /**
     * Execute the console command.
     * 
     * @return void
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
                    if ($processedCount >= $maxTotal) {
                        return false; 
                    }

                    $this->currentReasons = [];
                    $this->currentEvidence = [];

                    $score = $this->calculateBotScore($log, $config, $newLookups);
                    $isBot = $score >= $threshold;

                    if ($isBot) {
                        $botsDetected++;
                    }

                    $this->addEvidence('analyzed_at', now()->toDateTimeString());

                    $log->update([
                        'bot_score'    => min($score, 100),
                        'is_bot'       => $isBot,
                        'is_official_bot' => $this->isOfficialBot,
                        'bot_reasons'  => !empty($this->currentReasons) ? array_values(array_unique($this->currentReasons)) : null,
                        'bot_evidence' => $this->currentEvidence,
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

        $updatedRows = $this->performRetroactiveCleanup();
        $this->reportResults($processedCount, $botsDetected, $updatedRows, $isFull);
    }

    /**
     * Centralized method to add evidence data.
     * 
     * @param string $key
     * @param mixed $value
     * @return void
     */
    protected function addEvidence(string $key, $value): void
    {
        if ($value !== null) {
            $this->currentEvidence[$key] = $value;
        }
    }

    /**
     * Orchestrates the scoring process.
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @param int $newLookups
     * @return int Calculated bot score.
     */
    protected function calculateBotScore(VisitLog $log, array $config, int &$newLookups): int
    {
        $score = 0;
        $score += $this->calculateStaticPatternPoints($log, $config);
        $score += $this->checkBehavior($log, $config);
        $score += $this->checkNetwork($log, $config, $newLookups);
        $score += $this->checkCumulativePenalty($log, $config);

        return $score;
    }

    /**
     * Aggregates points from static pattern matches (UA, Honeypots, Referers).
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @return int
     */
    protected function calculateStaticPatternPoints(VisitLog $log, array $config): int
    {
        $score = 0;

        $score += $this->checkVisitDepth($log, $config);
        $score += $this->checkExplicitBots($log, $config);
        $score += $this->calculateSuspiciousUAPoints($log, $config);
        $score += $this->checkObsoleteOS($log, $config);
        $score += $this->calculateHoneypotPoints($log, $config);
        $score += $this->calculateRefererPoints($log, $config);

        return $score;
    }

    /**
     * Checks if the User-Agent explicitly identifies itself as a bot or crawler.
     * 
     * @param VisitLog $log
     * @param  array<string, mixed>  $config
     * @return int Returns 100 if an explicit bot is detected, 0 otherwise.
     */
    protected function checkExplicitBots(VisitLog $log, array $config): int
    {
        $ua = $log->user_agent;
        $this->isOfficialBot = false;

        if (empty($ua)) {
            return 0;
        }

        foreach ($config['explicit_bots'] ?? [] as $botSign) {
            if (stripos($ua, $botSign) !== false) {
                $this->currentReasons[] = 'explicit_bot';
                $this->addEvidence('bot_signature', $botSign);
                $this->isOfficialBot = true;
                
                return 100;
            }
        }

        return 0;
    }

/**
     * Identifies suspicious User-Agent patterns using both keyword matching 
     * and defined regular expressions.
     * 
     * This method flags empty User-Agents as critical bots and applies 
     * scores for common bot-pattern signatures like "zeroed" browser versions 
     * (e.g., 147.0.0.0) found in the 'ua_regex_patterns' configuration.
     *
     * @param  \Oleant\VisitAnalytics\Models\VisitLog  $log
     * @param  array<string, mixed>  $config
     * @return int Accumulated or immediate points based on UA suspiciousness.
     */
    protected function calculateSuspiciousUAPoints(VisitLog $log, array $config): int
    {
        $ua = trim((string)$log->user_agent);

        // 1. Critical anomaly: Missing or empty User-Agent
        if (empty($ua)) {
            $this->currentReasons[] = 'missing_user_agent';
            return 100;
        }

        $score = 0;

        // 2. Regex-based pattern matching (e.g., zeroed versions like \d+\.0\.0\.0)
        // We pull these directly from the 'ua_regex_patterns' config array
        foreach ($config['ua_regex_patterns'] ?? [] as $pattern => $weight) {
            // Ensure delimiters are present for preg_match
            $delimiter = (str_starts_with($pattern, '/') && str_ends_with($pattern, '/')) 
                ? $pattern 
                : '/' . $pattern . '/';

            if (@preg_match($delimiter, $ua)) {
                $score += (int)$weight;
                $this->currentReasons[] = 'ua_regex_match';
                $this->addEvidence('matched_regex', $pattern);
            }
        }

        // 3. Keyword-based matching
        foreach ($config['suspicious_ua'] ?? [] as $keyword) {
            $cleanKeyword = trim($keyword);
            if ($cleanKeyword === '') continue;

            if (mb_stripos($ua, $cleanKeyword) !== false) {
                $this->currentReasons[] = 'suspicious_ua';
                $this->addEvidence('ua_match_keyword', $cleanKeyword);
                
                $score += (int)($config['weights']['ua_suspicious'] ?? 50);
                break; 
            }
        }
        return min($score, 100);
    }

    /**
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @return int
     */
    protected function calculateHoneypotPoints(VisitLog $log, array $config): int
    {
        foreach ($config['honeypot_paths'] ?? [] as $path) {
            if (str_contains($log->url, $path)) {
                $this->currentReasons[] = 'honeypot_trap';
                $this->addEvidence('honeypot_url', $log->url);
                return 100; 
            }
        }
        return 0;
    }

/**
     * Analyzes Referer header and calculates penalties including "Snowball" logic,
     * self-referencing loops, and technical port leak detection.
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @return int
     */
    protected function calculateRefererPoints(VisitLog $log, array $config): int
    {
        $score = 0;
        $cumulativeConfig = $config['cumulative'] ?? [];

        // 1. Analyze missing Referer (Direct Navigation)
        if (empty($log->referer)) {
            $this->currentReasons[] = 'missing_referer';
            $this->addEvidence('referer_source', 'direct_navigation');
            
            $score = (int)($config['weights']['no_referer'] ?? 35);

            if ($cumulativeConfig['enabled'] ?? false) {
                $windowMinutes = (int)($cumulativeConfig['no_referer_window_minutes'] ?? 10);
                
                $directHitsHistory = VisitLog::where('ip_address', $log->ip_address)
                    ->whereNull('referer')
                    ->where('created_at', '>=', now()->subMinutes($windowMinutes))
                    ->where('id', '<', $log->id)
                    ->count();

                if ($directHitsHistory > 0) {
                    $multiplier = (int)($cumulativeConfig['no_referer_increment'] ?? 20);
                    $extraPoints = $directHitsHistory * $multiplier;
                    
                    $score += $extraPoints;
                    $this->currentReasons[] = 'referer_snowball';
                    $this->addEvidence('sequential_direct_hits', $directHitsHistory);
                    $this->addEvidence('lookback_window_minutes', $windowMinutes);
                }
            }
        }

        // 2. Analyze existing Referer
        if (!empty($log->referer)) {
            // Check for technical port leaks (cPanel, Plesk, etc.)
            $leakPorts = $config['port_leak'] ?? [];
            foreach ($leakPorts as $port) {
                if (str_contains($log->referer, ":$port")) {
                    $leakWeight = (int)($config['weights']['port_leak'] ?? 45);
                    $score += $leakWeight;
                    
                    $this->currentReasons[] = 'port_leak';
                    $this->addEvidence('leaked_port', $port);
                    $this->addEvidence('raw_referer', $log->referer);
                    break;
                }
            }

            // Normalization for Referer Loop detection
            $protocols = ['https://', 'http://'];
            $urlNoProtocol = str_replace($protocols, '', $log->url);
            $refNoProtocol = str_replace($protocols, '', $log->referer);
            
            $cleanUrl = rtrim(str_replace('www.', '', $urlNoProtocol), '/');
            $cleanRef = rtrim(str_replace('www.', '', $refNoProtocol), '/');

            // Detect if User-Agent is faking a self-referer loop
            if ($cleanUrl === $cleanRef) {
                $wasAlreadyHere = VisitLog::where('ip_address', $log->ip_address)
                    ->where('url', $log->url)
                    ->where('id', '<', $log->id)
                    ->exists();

                if (!$wasAlreadyHere) {
                    // Impossible: Referring from a page that hasn't been visited yet
                    $score += 100;
                    $this->currentReasons[] = 'impossible_self_referer';
                    $this->addEvidence('referer_loop', 'first_visit_with_self_ref');
                } else {
                    // Likely a page refresh or basic loop simulation
                    $score += (int)($config['weights']['referer_loop'] ?? 50);
                    $this->currentReasons[] = 'referer_loop';
                    $this->addEvidence('nav_type', 'page_refresh');
                }
            }
        }
        
        return $score;
    }

    /**
     * Checks the depth of the visit within a specific time window.
     * 
     * Identifies "single-page" visits with no referer, which is typical 
     * for slow crawlers or automated scanners performing targeted URL checks.
     *
     * @param  \Oleant\VisitAnalytics\Models\VisitLog  $log
     * @param  array<string, mixed>  $config
     * @return int Returns additional score points if no further activity is found.
     */
    protected function checkVisitDepth(VisitLog $log, array $config): int
    {
        // We only care about cases where there is no referer (direct entry)
        if (!empty($log->referer)) {
            return 0;
        }

        $windowMinutes = (int)($config['depth_check_window'] ?? 60);
        $from = Carbon::parse($log->created_at)->subMinutes($windowMinutes);
        $to = Carbon::parse($log->created_at)->addMinutes($windowMinutes);

        // Count other visits from the same IP within the +/- window
        $otherVisitsCount = VisitLog::where('ip_address', $log->ip_address)
            ->where('id', '!=', $log->id)
            ->whereBetween('created_at', [$from, $to])
            ->count();

        if ($otherVisitsCount === 0) {
            $this->currentReasons[] = 'single_page_scan';
            $this->addEvidence('visit_depth', '1_page_only');
            $this->addEvidence('check_window', "{$windowMinutes}min");

            return (int)($config['weights']['single_visit'] ?? 25);
        }

        return 0;
    }

    /**
     * Checks if the User-Agent reports an obsolete or suspicious operating system.
     * 
     * In 2026, systems like Windows XP, 7, 8 or ancient macOS versions 
     * are predominantly used by crawlers with outdated User-Agent lists.
     *
     * @param  \Oleant\VisitAnalytics\Models\VisitLog  $log
     * @param  array<string, mixed>  $config
     * @return int Points added for using an obsolete OS.
     */
    protected function checkObsoleteOS(VisitLog $log, array $config): int
    {
        $ua = $log->user_agent;
        $obsoletePatterns = $config['obsolete_os'] ?? ['Windows NT 5', 'Windows NT 6', 'Mac OS X 10'
        ];

        foreach ($obsoletePatterns as $pattern) {
            if (stripos($ua, $pattern) !== false) {
                $this->currentReasons[] = 'obsolete_os';
                $this->addEvidence('os_signature', $pattern);
                
                return (int)($config['weights']['obsolete_os'] ?? 60);
            }
        }

        return 0;
    }

    /**
     * Checks for request frequency and sequential navigation anomalies.
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @return int
     */
    protected function checkBehavior(VisitLog $log, array $config): int
    {
        if (!$log->ip_address) return 0;

        $score = 0;
        $cumulativeConfig = $config['cumulative'] ?? [];
        
        $window = (int)($config['time_window'] ?? 5);
        $from = Carbon::parse($log->created_at)->subMinutes($window);

        $historyCount = VisitLog::where('ip_address', $log->ip_address)
            ->whereBetween('created_at', [$from, $log->created_at])
            ->count();

        $maxRate = (($config['rate_limit_per_minute'] ?? 30) * $window);
        if ($historyCount > $maxRate) {
            $score += (int)($config['weights']['rate'] ?? 50);
            $this->currentReasons[] = 'high_request_rate';
            $this->addEvidence('request_rate_metric', "{$historyCount}/{$window}min");
        }

        $prev = VisitLog::where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->orderBy('id', 'desc')
            ->first();

        if ($prev) {
            $diff = abs($log->created_at->timestamp - $prev->created_at->timestamp);
            $this->addEvidence('request_interval_sec', $diff);

            $minInterval = (int)($config['min_interval'] ?? 2);
            if ($diff < $minInterval) {
                $baseWeight = (int)($config['weights']['speed_anomaly'] ?? 50);
                $penalty = ($diff === 0) ? ($baseWeight * 2) : $baseWeight;
                
                $score += $penalty;
                $this->currentReasons[] = 'speed_anomaly';
            }

            // Логика разрыва цепочки Referer
            if (empty($log->referer)) {
                if ($prev->url === $log->url) {
                    // Это обычный повтор/обновление той же страницы
                    $this->addEvidence('nav_type', 'page_refresh');
                } else {
                    // А вот это странно: страница сменилась, а реферера нет (имитация перехода без заголовков)
                    $increment = (int)($cumulativeConfig['no_referer_increment'] ?? 20);
                    
                    // Берем скор предыдущей записи и добавляем инкремент
                    $score += ($prev->bot_score + $increment);
                    
                    $this->currentReasons[] = 'broken_referer_chain';
                    $this->addEvidence('prev_page', $prev->url);
                    $this->addEvidence('inherited_score', $prev->bot_score);
                }
            }
        }
        return $score;
    }

    /**
     * Validates IP via Reverse DNS and checks for Datacenter patterns.
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @param int $newLookups
     * @return int
     */
    protected function checkNetwork(VisitLog $log, array $config, int &$newLookups): int
    {
        if (!$log->ip_address) return 0;

        if (isset(static::$dnsCache[$log->ip_address])) {
            $cached = static::$dnsCache[$log->ip_address];
            if ($cached['reason']) $this->currentReasons[] = $cached['reason'];
            if ($cached['host']) $this->addEvidence('cached_ptr_record', $cached['host']);
            return $cached['score'];
        }

        $newLookups++;
        $dnsScore = 0;
        $reason = null;
        $foundHost = null;
        
        $lookupIp = str_ends_with($log->ip_address, '.0') 
            ? substr($log->ip_address, 0, strrpos($log->ip_address, '.')) . '.1' 
            : $log->ip_address;

        try {
            $host = gethostbyaddr($lookupIp);
            if ($host && $host !== $lookupIp) {
                $foundHost = $host;
                foreach ($config['datacenter_check']['keywords'] ?? [] as $kw) {
                    if (str_contains(strtolower($host), $kw)) {
                        $dnsScore = (int)($config['weights']['datacenter'] ?? 100);
                        $reason = 'datacenter_ip';
                        $this->addEvidence('ptr_record_match', $host);
                        break;
                    }
                }
            } else {
                $dnsScore = (int)($config['weights']['no_dns_record'] ?? 50);
                $reason = 'no_ptr_record';
                $this->addEvidence('network_status', 'no_reverse_dns');
            }
        } catch (Exception $e) { }

        static::$dnsCache[$log->ip_address] = [
            'score' => $dnsScore, 
            'reason' => $reason,
            'host' => $foundHost
        ];
        
        if ($reason) $this->currentReasons[] = $reason;

        return $dnsScore;
    }

    /**
     * Checks if the IP address has a history of bot detections.
     * 
     * @param VisitLog $log
     * @param array<string, mixed> $config
     * @return int
     */
    protected function checkCumulativePenalty(VisitLog $log, array $config): int
    {
        if (!($config['cumulative']['enabled'] ?? false)) return 0;

        $hours = (int)($config['cumulative']['history_window_hours'] ?? 24);
        $pastOffenses = VisitLog::where('ip_address', $log->ip_address)
            ->where('is_bot', true)
            ->where('created_at', '>=', now()->subHours($hours))
            ->where('id', '<', $log->id)
            ->count();

        if ($pastOffenses > 0) {
            $this->currentReasons[] = 'repeat_offender';
            $this->addEvidence('past_24h_offenses', $pastOffenses);
            return $pastOffenses * (int)($config['cumulative']['penalty_multiplier'] ?? 10);
        }

        return 0;
    }

/**
     * Performs retroactive cleanup of visit logs.
     * 
     * This method identifies all previously "clean" records (is_bot = false) 
     * associated with IP addresses that have been flagged as bots. It looks at 
     * both IPs detected in the current execution and those identified within 
     * the last 24 hours to ensure historical logs are correctly updated.
     *
     * @return int The number of updated records.
     */
    protected function performRetroactiveCleanup(): int
    {
        // 1. Get IPs identified as bots in the current session
        $currentBatchIps = $this->detectedIps;

        // 2. Fetch IPs identified as bots within the last 24 hours to handle re-analysis
        $recentBotIps = VisitLog::where('is_bot', true)
            ->where('processed_at', '>=', now()->subDay())
            ->distinct()
            ->pluck('ip_address')
            ->toArray();

        // Combine and unique the IP list
        $allBadIps = array_unique(array_merge($currentBatchIps, $recentBotIps));

        if (empty($allBadIps)) {
            return 0;
        }

        /**
         * Logic:
         * 1. Filter by IPs confirmed as bots (current batch + recent history).
         * 2. Target only records currently marked as non-bots.
         * 3. Use a wide lookback window (60 days) to catch historical logs 
         *    regardless of when they were first created or processed.
         */
        return VisitLog::whereIn('ip_address', $allBadIps)
            ->where('is_bot', false)
            ->where('created_at', '>=', now()->subDays(60))
            ->update([
                'is_bot' => true,
                'bot_score' => 100,
                'bot_reasons' => ['retroactive_cleanup'],
                'bot_evidence' => json_encode([
                    'source' => 'retroactive_analysis',
                    'detected_at' => now()->toDateTimeString(),
                    'reason' => 'IP identified as bot based on current or recent session behavior'
                ]),
                // Mark as processed to reflect the new state after re-analysis
                'processed_at' => now(),
            ]);
    }

    /**
     * Display or log analysis results.
     * 
     * @param int $processed
     * @param int $bots
     * @param int $retroactive
     * @param bool $isFull
     * @return void
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
                $timestamp, $processed, $bots, $rate, $retroactive
            ));
        }
    }

    /**
     * Print startup configuration info.
     * 
     * @param int $max
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
     * 
     * @param float $startTime
     * @param int $newLookups
     * @param int $total
     * @return void
     */
    protected function printChunkSummary(float $startTime, int $newLookups, int $total): void
    {
        $time = round(microtime(true) - $startTime, 2);
        $this->newLine();
        $this->info("Chunk processed: {$time}s | New DNS Lookups: {$newLookups} | Total: {$total}");
    }
}