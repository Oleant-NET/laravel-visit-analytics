<?php

namespace Oleant\VisitAnalytics\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Oleant\VisitAnalytics\Database\Factories\VisitLogFactory;

/**
 * @property string $ip_address
 * @property string $user_agent
 * @property string $url
 * @property string $referer
 * @property array $payload
 * @property \DateTime $processed_at
 * @property int $bot_score
 * @property bool $is_bot
 * @property \DateTime $created_at
 */
class VisitLog extends Model
{
    use HasFactory;

    // We handle created_at manually in booted()
    public $timestamps = false;

    protected $dateFormat = 'Y-m-d H:i:s.v';

    protected $fillable = [
        'ip_address',
        'user_agent',
        'target_headers',
        'fingerprint_hash',
        'url',
        'referer',
        'payload',
        'processed_at',
        'anonymized_at',
        'bot_score',
        'bot_reasons',
        'bot_evidence',
        'is_bot',
        'is_official_bot',
    ];

    protected $casts = [
        'payload'      => 'array',
        'processed_at' => 'datetime',
        'anonymized_at' => 'datetime',
        'created_at'   => 'datetime',
        'bot_score'    => 'integer',
        'is_bot'       => 'boolean',
        'is_official_bot' => 'boolean',
        'bot_reasons'  => 'array',
        'bot_evidence' => 'array',
        'target_headers' => 'array',
    ];

    /**
     * Set the creation date on record start.
     */
    protected static function booted()
    {
        static::creating(function ($model) {
            // Ensure created_at is set if not provided
            if (!$model->created_at) {
                $model->created_at = $model->freshTimestamp();
            }
        });
    }

    /**
     * Create a new factory instance for the model.
     * 
     * @return \Illuminate\Database\Eloquent\Factories\Factory
     */
    protected static function newFactory()
    {
        return VisitLogFactory::new();
    }
}