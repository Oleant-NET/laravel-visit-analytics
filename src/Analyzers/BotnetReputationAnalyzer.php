<?php

namespace Oleant\VisitAnalytics\Analyzers;

use Oleant\VisitAnalytics\Contracts\BotAnalyzerInterface;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Services\BotnetService;
use Log;

/**
 * Class BotnetReputationAnalyzer
 * * This analyzer cross-references the visitor's User-Agent against a database
 * of known distributed botnet fingerprints to identify coordinated attacks.
 */
class BotnetReputationAnalyzer implements BotAnalyzerInterface
{
    /**
     * @var BotnetService
     */
    protected BotnetService $botnetService;

    /**
     * BotnetReputationAnalyzer constructor.
     * * @param BotnetService $botnetService
     */
    public function __construct(BotnetService $botnetService)
    {
        $this->botnetService = $botnetService;
    }

    /**
     * Analyze the request for known botnet signatures.
     *
     * @param VisitLog $log
     * @param AnalysisState $state
     * @param array $params
     * @return void
     */
    public function analyze(VisitLog $log, AnalysisState $state, array $params = []): void
    {
        // 1. Skip if it's already identified as an official bot to save resources
        if ($state->isOfficialBot) {
            return;
        }

        $ua = $log->user_agent;

        if (empty($ua)) {
            return;
        }

        // 2. Safety check for whitelisted patterns 
        if (!$this->shouldAnalyze($ua, $params)) {
            return;
        }

        // 3. Query the fingerprint database and record evidence if matched
        if ($this->botnetService->isKnownBotnet($ua)) {
            $points = (int)($params['weights']['known_botnet'] ?? 100);

            // Log the detection for real-time monitoring
            Log::warning('Botnet signature detected', [
                'ip' => $log->ip_address,
                'user_agent' => $ua,
                'points' => $points
            ]);

            /**
             * Record the match as evidence.
             * Using add() to ensure proper hierarchy in AnalysisState.
             */
            $state->add(
                $points, 
                'botnet_match', 
                [
                    'signature' => 'known_botnet_fingerprint',
                    'points_awarded' => $points
                ]
            );
        }
    }

    /**
     * Determine if the UA should be checked against the botnet database.
     * * @param string $userAgent
     * @param array $params
     * @return bool
     */
    protected function shouldAnalyze(string $userAgent, array $params): bool
    {
        $patterns = $params['ignore_patterns'] ?? [];
        
        $ignorePatterns = is_callable($patterns) ? $patterns() : (array) $patterns;

        foreach ($ignorePatterns as $pattern) {
            if (!empty($pattern) && stripos($userAgent, $pattern) !== false) {
                return false;
            }
        }

        return true;
    }
}