<?php

namespace Oleant\VisitAnalytics\Traits;

use Oleant\VisitAnalytics\Models\VisitLog;
use Carbon\Carbon;

trait QueriesVisitHistory
{
    /**
     * Checks if the first log in the recent window had a 'none' fetch site,
     * indicating a legitimate initial direct hit.
     */
    protected function isInitialDirectHit(VisitLog $log, int $windowMinutes): bool
    {
        $sessionStart = $log->created_at->copy()->subMinutes($windowMinutes);

        $firstLog = VisitLog::withoutGlobalScopes()
            ->where('ip_address', $log->ip_address)
            ->where('id', '<', $log->id)
            ->where('created_at', '>=', $sessionStart->toDateTimeString())
            ->orderBy('id', 'asc')
            ->first();

        return ($firstLog->target_headers['sec-fetch-site'] ?? null) === 'none';
    }

    /**
     * Counts sequential direct hits within a specified time window.
     */
    protected function getSequentialDirectHitsCount(VisitLog $log, int $windowMinutes): int
    {
        $query = VisitLog::where('ip_address', $log->ip_address)
            ->where(fn($q) => $q->whereNull('referer')->orWhere('referer', ''))
            ->where('created_at', '>=', $log->created_at->copy()->subMinutes($windowMinutes));

        if ($log->exists) {
            $query->where('id', '<', $log->id);
        }

        return $query->count();
    }

    /**
     * Checks if the user has visited the specified URL before in the current session.
     */
    protected function hasVisitedUrlBefore(string $ipAddress, string $url, int $currentLogId): bool
    {
        return VisitLog::where('ip_address', $ipAddress)
            ->where('url', $url)
            ->where('id', '<', $currentLogId)
            ->exists();
    }
}