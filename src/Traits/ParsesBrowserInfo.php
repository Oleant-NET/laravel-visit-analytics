<?php

namespace Oleant\VisitAnalytics\Traits;

use Oleant\VisitAnalytics\Models\VisitLog;

trait ParsesBrowserInfo
{
    /**
     * Extracts browser name and major version.
     * 
     * Uses 'sec-ch-ua' Client Hints as the primary source for high reliability,
     * with a fallback to traditional User-Agent string.
     *
     * @param VisitLog $log
     * @return array{name: string, version: int}|null
     */
    protected function extractBrowserInfo(VisitLog $log): ?array
    {
        // 1. Primary: Extract from Client Hints (sec-ch-ua)
        $headers = $log->target_headers;
        $ch = $headers['sec-ch-ua'] ?? '';
        
        if ($ch && preg_match('/"Google Chrome";v="(\d+)"/', $ch, $matches)) {
            return [
                'name'    => 'chrome', 
                'version' => (int) $matches[1]
            ];
        }

        // 2. Secondary: Fallback to User-Agent parsing
        if (preg_match('/Chrome\/(\d+)/', $log->user_agent, $matches)) {
            return [
                'name'    => 'chrome', 
                'version' => (int) $matches[1]
            ];
        }

        return null;
    }
}