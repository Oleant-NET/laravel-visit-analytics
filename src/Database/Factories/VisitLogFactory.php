<?php

namespace Oleant\VisitAnalytics\Database\Factories;

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\Oleant\VisitAnalytics\Models\VisitLog>
 */
class VisitLogFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var string
     */
    protected $model = VisitLog::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'ip_address'   => $this->faker->ipv4(),
            'user_agent'   => $this->faker->userAgent(),
            'url'          => $this->faker->url(),
            'is_bot'       => false,
            'bot_score'    => 0,
            'bot_reasons'  => [],
            'bot_evidence' => [],
            'processed_at' => null,
            'created_at'   => now(),
        ];
    }
}