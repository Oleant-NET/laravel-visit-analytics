<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Create the table for storing anonymized visit data.
     */
    public function up(): void
    {
        Schema::create('visit_logs', function (Blueprint $table) {
            $table->id();
            
            // Anonymized IP address (e.g., 192.168.1.0) for privacy compliance
            $table->string('ip_address', 45)->nullable();
            
            // Full User Agent string to identify browser and device type
            $table->text('user_agent')->nullable();
            
            // The destination URL path that was visited
            $table->string('url')->index();
            
            // The source URL (where the visitor came from)
            $table->text('referer')->nullable();

            // JSON storage for whitelisted query parameters (UTM tags, ref, etc.)
            $table->json('payload')->nullable();

            // Single timestamp for the event. Indexed for faster analytics reporting.
            $table->timestamp('created_at')->useCurrent()->index();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('visit_logs');
    }
};