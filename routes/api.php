<?php

use App\Http\Controllers\AuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::prefix('auth')->group(function () {
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'me']);

    Route::post('/password/reset/send-link', [AuthController::class, 'sendPasswordResetLink'])->middleware('throttle:3,1');
    Route::post('/password/reset', [AuthController::class, 'resetPassword']);

    Route::post('/email/verify', [AuthController::class, 'verifyEmail']);
    Route::post('/email/resend-link', [AuthController::class, 'resendEmailVerificationLink']);
});
