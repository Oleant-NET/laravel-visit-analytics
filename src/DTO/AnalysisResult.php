<?php 

namespace Oleant\VisitAnalytics\DTO;

class AnalysisResult
{
    public function __construct(
        public int $score,
        public bool $isBot,
        public array $reasons,
        public array $evidence,
        public bool $isOfficialBot,
        public int $newLookups = 0
    ) {}
}