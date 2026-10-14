<?php

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\Http\Controllers;
use LaraGram\Support\Facades\Route;

Route::post('/token', [Controllers\AccessTokenController::class, 'issueToken'])
    ->middleware('throttle')
    ->name('token');

Route::post('/revoke', Controllers\RevokeTokenController::class)
    ->middleware('throttle')
    ->name('token.revoke');

Route::get('/authorize', [Controllers\AuthorizationController::class, 'authorize'])
    ->middleware('web')
    ->name('authorizations.authorize');

if (Citadel::$deviceCodeGrantEnabled) {
    Route::get('/device', Controllers\DeviceUserCodeController::class)
        ->middleware('web')
        ->name('device');

    Route::post('/device/code', Controllers\DeviceCodeController::class)
        ->middleware('throttle')
        ->name('device.code');
}

if (Citadel::$telegramGrantEnabled) {
    Route::get('/telegram/login', Controllers\TelegramLoginController::class)
        ->middleware('web')
        ->name('telegram.login');
}

$guard = config('citadel.oauth.guard');

Route::middleware(['web', $guard ? 'auth:'.$guard : 'auth'])->group(function () {
    Route::post('/token/refresh', [Controllers\TransientTokenController::class, 'refresh'])
        ->name('token.refresh');

    Route::post('/authorize', [Controllers\ApproveAuthorizationController::class, 'approve'])
        ->name('authorizations.approve');

    Route::delete('/authorize', [Controllers\DenyAuthorizationController::class, 'deny'])
        ->name('authorizations.deny');

    if (Citadel::$deviceCodeGrantEnabled) {
        Route::get('/device/authorize', Controllers\DeviceAuthorizationController::class)
            ->name('device.authorizations.authorize');

        Route::post('/device/authorize', Controllers\ApproveDeviceAuthorizationController::class)
            ->name('device.authorizations.approve');

        Route::delete('/device/authorize', Controllers\DenyDeviceAuthorizationController::class)
            ->name('device.authorizations.deny');
    }

    if (Citadel::$registersJsonApiRoutes) {
        Route::get('/tokens', [Controllers\AuthorizedAccessTokenController::class, 'forUser'])->name('tokens.index');
        Route::delete('/tokens/{token_id}', [Controllers\AuthorizedAccessTokenController::class, 'destroy'])->name('tokens.destroy');

        Route::get('/clients', [Controllers\ClientController::class, 'forUser'])->name('clients.index');
        Route::post('/clients', [Controllers\ClientController::class, 'store'])->name('clients.store');
        Route::put('/clients/{client_id}', [Controllers\ClientController::class, 'update'])->name('clients.update');
        Route::delete('/clients/{client_id}', [Controllers\ClientController::class, 'destroy'])->name('clients.destroy');

        Route::get('/scopes', [Controllers\ScopeController::class, 'all'])->name('scopes.index');

        Route::get('/personal-access-tokens', [Controllers\PersonalAccessTokenController::class, 'forUser'])->name('personal.tokens.index');
        Route::post('/personal-access-tokens', [Controllers\PersonalAccessTokenController::class, 'store'])->name('personal.tokens.store');
        Route::delete('/personal-access-tokens/{token_id}', [Controllers\PersonalAccessTokenController::class, 'destroy'])->name('personal.tokens.destroy');
    }
});
