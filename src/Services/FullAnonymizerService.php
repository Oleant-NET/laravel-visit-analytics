<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;

/**
 * Class IpAnonymizerService
 *
 * Provides functionality to mask IP addresses based on compliance requirements (GDPR/DSGVO).
 * Supports both IPv4 and IPv6, and respects asynchronous processing modes.
 */
class FullAnonymizerService
{
    /**
     * Configuration
     *
     * @var array
     */
    protected array $config = [];

    /**
     * IP Anonymizator
     *
     * @var IpAnonymizerService $ipAnonymizerService
     */
    protected IpAnonymizerService $ipAnonymizerService;

    /**
     * UA | Header | fingerprint_hash Anonymizator
     *
     * @var FingerprintAnonymizerService $fingerprintAnonymizerService
     */
    protected FingerprintAnonymizerService $fingerprintAnonymizerService;

    /**
     * Constructor
     */
    public function __construct(
        IpAnonymizerService $ipAnonymizerService, 
        FingerprintAnonymizerService $fingerprintAnonymizerService
    ) {
        $this->ipAnonymizerService = $ipAnonymizerService;
        $this->fingerprintAnonymizerService = $fingerprintAnonymizerService;
    }

    /**
     * Performs deferred anonymization of processed visit logs.
     * This method masks IP addresses for logs that have already been processed 
     * and have exceeded the retention period defined in the configuration. 
     * It ensures that sensitive data is kept only as long as necessary for 
     * retroactive analysis and cluster detection.
     *
     * @return int
     */
    public function runDeferredAnonymization(): int
    {
        $config = config('visit-analytics-collection.anonymization', []);
 
        $retentionMinutes = (int) ($config['anonymize_retention_minutes'] ?? 30);
        $anonymizeBots = (bool) ($config['anonymize_bots'] ?? true);
        $thresholdTime = now()->subMinutes($retentionMinutes);

        // Fetch logs that are processed, pending anonymization, and past the retention window
        $query = VisitLog::whereNotNull('processed_at')
            ->whereNull('anonymized_at')
            ->where('created_at', '<', $thresholdTime);

        // Exclude bots if bot anonymization is disabled to preserve raw data
        if (!$anonymizeBots) {
            $query->where('is_bot', false);
        }

        $count = 0;

        $query->chunkById(500, function ($logs) use (&$count, $anonymizeBots) {
            foreach ($logs as $log) {
                // 1. IP Anonymization (handled based on your logic)
                $ip = $this->ipAnonymizerService->handle($log->ip_address, true);
                
                // 2. Fingerprint Anonymization (conditional)
                // Proceed with full anonymization
                $fingerprint = $this->fingerprintAnonymizerService->handle($log);
                
                $log->update([
                    'ip_address'       => $ip,
                    'user_agent'       => $fingerprint['user_agent'] ?? $log->user_agent,
                    'target_headers'   => $fingerprint['target_headers'] ?? $log->target_headers,
                    'fingerprint_hash' => $fingerprint['fingerprint_hash'] ?? $log->fingerprint_hash,
                    'anonymized_at'    => now(),
                ]);
                
                $count++;
            }
        });

        return $count;
    }
}