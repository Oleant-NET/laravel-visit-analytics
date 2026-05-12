<?php

namespace Oleant\VisitAnalytics\Database\Migrations;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Class CreateBotnetFingerprintsTable
 * * This table stores identified botnet signatures based on User-Agent patterns.
 * It allows the system to perform high-speed lookups during the request cycle.
 */
return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('botnet_fingerprints', function (Blueprint $table) {
            $table->id();
            
            /** * SHA-256 hash of the User-Agent string.
             * Unique index ensures fast lookup and prevents duplicates.
             */
            $table->char('ua_hash', 64)->unique();
            
            /** * Full User-Agent string for reference and debugging.
             */
            $table->text('user_agent');
            
            /** * Total number of hits recorded for this specific fingerprint.
             */
            $table->integer('hits_count')->default(0);
            
            /** * Number of distinct IP addresses used by this botnet.
             */
            $table->integer('unique_ips_count')->default(0);
            
            /** * Brief description of why this UA was flagged (e.g., 'distributed_cluster_detected').
             */
            $table->string('detection_reason')->nullable();
            
            /** * Timestamps for initial detection and most recent activity.
             */
            $table->timestamp('detected_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            
            /** * Status flag to enable/disable the fingerprint without deleting the record.
             */
            $table->boolean('is_active')->default(true)->index();

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('botnet_fingerprints');
    }
};