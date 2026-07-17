<?php

namespace Oleant\VisitAnalytics\Analyzers\Rules\Base;

use Oleant\VisitAnalytics\Contracts\RuleInterface;

/**
 * Abstract Class AbstractBotnetRule
 * 
 * Base class for all behavioral analysis rules. Provides shared utility methods
 * for request inspection and data normalization.
 */
abstract class AbstractBotnetRule implements RuleInterface
{
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