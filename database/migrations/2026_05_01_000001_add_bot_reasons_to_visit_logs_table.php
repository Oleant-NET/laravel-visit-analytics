<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            // Core classification flags
            $table->boolean('is_official_bot')->default(false)->index()->after('is_bot');

            // Structured analysis data
            // bot_reasons: [{"id": "string", "label": "string", "score": int}]
            $table->json('bot_reasons')->nullable()->after('is_official_bot');
            
            // bot_data: {"key": "value"} - raw evidence data
            $table->json('bot_evidence')->nullable()->after('bot_reasons');

            // Compound index for performance (behavioral analysis & "Snowball" effect)
            $table->index(['ip_address', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->dropIndex(['is_official_bot']);
            $table->dropIndex(['ip_address', 'created_at']);
            $table->dropColumn([
                'is_official_bot',
                'bot_reasons',
                'bot_evidence'
            ]);
        });
    }
};