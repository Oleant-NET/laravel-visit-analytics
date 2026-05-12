<?php

namespace Oleant\VisitAnalytics\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Oleant\VisitAnalytics\Models\BotnetFingerprint;
use Carbon\Carbon;

/**
 * Class BotnetService
 * Handles distributed botnet detection, fingerprint management, and reputation lookups.
 */
class BotnetService
{
    /**
     * @var array The botnet analyzer specific parameters.
     */
    protected array $params;

    /**
     * BotnetService constructor.
     */
    public function __construct()
    {
        // We load the params once during instantiation
        $this->params = config('visit-analytics.detection_engine.analyzers.botnet.params', []);
    }

    /**
     * Check if a User-Agent signature is present in the botnet database.
     *
     * @param string $userAgent
     * @return bool
     */
    public function isKnownBotnet(string $userAgent): bool
    {
        $hash = $this->generateHash($userAgent);

        $fingerprint = BotnetFingerprint::where('ua_hash', $hash)
            ->where('is_active', true)
            ->first();

        if ($fingerprint) {
            $this->hit($fingerprint);
            return true;
        }

        return false;
    }

    /**
     * Generate a unique fingerprint hash for a User-Agent.
     *
     * @param string $userAgent
     * @return string
     */
    public function generateHash(string $userAgent): string
    {
        return hash('sha256', $userAgent);
    }

    /**
     * Record a botnet hit and update the 'last_seen_at' timestamp with throttling.
     *
     * @param BotnetFingerprint $fingerprint
     * @return void
     */
    protected function hit(BotnetFingerprint $fingerprint): void
    {
        $throttle = $this->params['update_throttle'] ?? 300;
        $cacheKey = "botnet_hit_{$fingerprint->ua_hash}";

        if (!Cache::has($cacheKey)) {
            $fingerprint->update([
                'last_seen_at' => Carbon::now(),
            ]);
            
            Cache::put($cacheKey, true, $throttle);
        }
    }

    /**
     * Analyze recent visit logs to identify new distributed botnet clusters.
     *
     * @return int Number of new botnets detected.
     */
    public function detectNewClusters(): int
    {
        $windowHours = $this->params['analysis_window_hours'] ?? 24;
        $ipThreshold = $this->params['ip_threshold'] ?? 10;
        $hitsThreshold = $this->params['hits_threshold'] ?? 50;

        // Resolve ignore patterns (closures supported)
        $ignore = $this->params['ignore_patterns'] ?? [];
        $ignorePatterns = is_callable($ignore) ? $ignore() : (array) $ignore;

        $suspiciousUAs = DB::table('visit_logs')
            ->select('user_agent', DB::raw('count(*) as hits'), DB::raw('count(distinct ip_address) as unique_ips'))
            ->where('created_at', '>=', Carbon::now()->subHours($windowHours))
            ->where(function ($query) use ($ignorePatterns) {
                foreach ($ignorePatterns as $pattern) {
                    if (!empty($pattern)) {
                        $query->where('user_agent', 'NOT LIKE', "%{$pattern}%");
                    }
                }
            })
            ->groupBy('user_agent')
            ->having('unique_ips', '>=', $ipThreshold)
            ->having('hits', '>=', $hitsThreshold)
            ->get();

        $newCount = 0;

        foreach ($suspiciousUAs as $item) {
            $hash = $this->generateHash($item->user_agent);

            $record = BotnetFingerprint::updateOrCreate(
                ['ua_hash' => $hash],
                [
                    'user_agent' => $item->user_agent,
                    'detection_reason' => "Detected cluster: {$item->unique_ips} IPs, {$item->hits} hits in window.",
                    'hits_count' => $item->hits,
                    'unique_ips_count' => $item->unique_ips,
                    'is_active' => true,
                    'last_seen_at' => Carbon::now(),
                ]
            );

            if ($record->wasRecentlyCreated) {
                $newCount++;
            }
        }

        return $newCount;
    }
}