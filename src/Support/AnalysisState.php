<?php

namespace Oleant\VisitAnalytics\Support;

/**
 * Class AnalysisState
 * 
 * Persistent state object that traverses through the chain of analyzers
 * to collect scores, reasons, and technical evidence.
 */
class AnalysisState
{
    /** @var bool Indicates if the visitor is a verified/official search engine bot */
    public bool $isOfficialBot = false;

    /** @var int Tracks the number of external network/DNS lookups performed */
    public int $newLookups = 0;

    /**
     * @param int $score Accumulated threat score (0-100)
     * @param array $reasons List of identified threat markers
     * @param array $evidence Detailed technical data for debugging/logging
     */
    public function __construct(
        public int $score = 0,
        public array $reasons = [],
        public array $evidence = []
    ) {}

    /**
     * Increment the threat score and log the reason with supporting evidence.
     *
     * @param int $points Points to add to the total score.
     * @param string $reason Slug identifying the detection logic.
     * @param array $data Key-value pairs of technical evidence.
     * @return void
     */
    public function add(int $points, string $reason, array $data = []): void
    {
        $this->score += $points;
        $this->reasons[] = $reason;
        
        if (!empty($data)) {
            $this->evidence[$reason] = $data;
        }
    }

    /**
     * Adds diagnostic evidence data without affecting the total bot score.
     *
     * Used to store metadata (like PTR records, matched keywords, or timing) 
     * that helps during manual log review.
     *
     * @param string $key   Unique identifier for the evidence (e.g., 'ptr_record').
     * @param mixed  $value The actual data to store (string, int, array, etc.).
     * @return void
     */
    public function addEvidence(string $key, mixed $value): void
    {
        $this->evidence[$key] = $value;
    }

    /**
     * Gets the total accumulated bot probability score.
     *
     * @return int Value typically ranging from 0 to 100+.
     */
    public function getScore(): int
    {
        return $this->score;
    }

    /**
     * Gets the list of unique reasons/tags identified during analysis.
     *
     * @return array<int, string> Array of strings (e.g., ['datacenter_ip', 'high_request_rate']).
     */
    public function getReasons(): array
    {
        return $this->reasons;
    }

    /**
     * Gets all collected evidence/metadata.
     *
     * @return array<string, mixed> Key-value pairs of diagnostic data.
     */
    public function getEvidence(): array
    {
        return $this->evidence;
    }

    /**
     * Gets a specific piece of evidence by key.
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function getEvidenceValue(string $key, mixed $default = null): mixed
    {
        return $this->evidence[$key] ?? $default;
    }
}