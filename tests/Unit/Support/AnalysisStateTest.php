<?php

namespace Oleant\VisitAnalytics\Tests\Unit\Support;

use Oleant\VisitAnalytics\Support\AnalysisState;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Test;

class AnalysisStateTest extends TestCase
{
    #[Test]
    public function it_accumulates_scores_correctly(): void
    {
        $state = new AnalysisState();
        $state->add(20, 'reason_1');
        $state->add(30, 'reason_2');

        $this->assertEquals(50, $state->getScore());
        $this->assertCount(2, $state->getReasons());
    }

    #[Test]
    public function it_merges_evidence_data(): void
    {
        $state = new AnalysisState();
        $state->add(10, 'reason', ['key1' => 'val1']);
        $state->addEvidence('key2', 'val2');

        $evidence = $state->getEvidence();
        $this->assertArrayHasKey('key1', $evidence);
        $this->assertArrayHasKey('key2', $evidence);
        $this->assertEquals('val1', $evidence['key1']);
        $this->assertEquals('val2', $evidence['key2']);
    }

    #[Test]
    public function it_tracks_official_bot_status(): void
    {
        $state = new AnalysisState();
        $this->assertFalse($state->isOfficialBot);
        
        $state->isOfficialBot = true;
        $this->assertTrue($state->isOfficialBot);
    }
}