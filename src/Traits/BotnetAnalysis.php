<?php

namespace Oleant\VisitAnalytics\Traits;

/**
 * Trait BotnetAnalysis
 * 
 * Provides shared utility methods for botnet/cluster analysis.
 */
trait BotnetAnalysis
{
    /**
     * Check if the User-Agent is on the whitelist.
     * 
     * @param string|null $userAgent
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