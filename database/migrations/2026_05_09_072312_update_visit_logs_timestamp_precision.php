<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
public function up(): void
{
    $driver = \Illuminate\Support\Facades\DB::getDriverName();

    if (in_array($driver, ['mysql', 'mariadb'])) {
        \Illuminate\Support\Facades\DB::statement('ALTER TABLE visit_logs MODIFY created_at TIMESTAMP(3) NULL');
    } else {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->timestamp('created_at', 3)->nullable()->change();
        });
    }
}

    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->timestamp('created_at')->nullable()->change();
        });
    }
};