<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        \Illuminate\Support\Facades\DB::statement('ALTER TABLE visit_logs MODIFY created_at TIMESTAMP(3) NULL');
    }

    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->timestamp('created_at')->nullable()->change();
        });
    }
};