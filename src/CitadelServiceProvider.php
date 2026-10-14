<?php

namespace LaraGram\Citadel;

use DateInterval;
use LaraGram\Auth\Events\Logout;
use LaraGram\Citadel\Contracts\ApprovedDeviceAuthorizationResponse as ApprovedDeviceAuthorizationResponseContract;
use LaraGram\Citadel\Contracts\AuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeniedDeviceAuthorizationResponse as DeniedDeviceAuthorizationResponseContract;
use LaraGram\Citadel\Contracts\DeviceAuthorizationViewResponse;
use LaraGram\Citadel\Contracts\DeviceUserCodeViewResponse;
use LaraGram\Citadel\Http\Controllers\AuthorizationController;
use LaraGram\Citadel\Http\Controllers\AuthorizationServerMetadataController;
use LaraGram\Citadel\Http\Controllers\CsrfCookieController;
use LaraGram\Citadel\Http\Controllers\DeviceAuthorizationController;
use LaraGram\Citadel\Http\Controllers\TelegramLoginController;
use LaraGram\Citadel\Http\Middleware\CheckAbilities;
use LaraGram\Citadel\Http\Middleware\CheckForAnyAbility;
use LaraGram\Citadel\Http\Middleware\EnsureFrontendRequestsAreStateful;
use LaraGram\Citadel\Http\Responses\ApprovedDeviceAuthorizationResponse;
use LaraGram\Citadel\Http\Responses\DeniedDeviceAuthorizationResponse;
use LaraGram\Citadel\Http\Responses\SimpleViewResponse;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Citadel\OAuth\CryptKey;
use LaraGram\Citadel\OAuth\Grants\AuthCodeGrant;
use LaraGram\Citadel\OAuth\Grants\ClientCredentialsGrant;
use LaraGram\Citadel\OAuth\Grants\DeviceCodeGrant;
use LaraGram\Citadel\OAuth\Grants\ImplicitGrant;
use LaraGram\Citadel\OAuth\Grants\PasswordGrant;
use LaraGram\Citadel\OAuth\Grants\RefreshTokenGrant;
use LaraGram\Citadel\OAuth\Grants\TelegramGrant;
use LaraGram\Citadel\OAuth\ResourceServer;
use LaraGram\Citadel\Telegram\TelegramAuthenticator;
use LaraGram\Contracts\Auth\StatefulGuard;
use LaraGram\Encryption\Encrypter;
use LaraGram\Support\Facades\Auth;
use LaraGram\Support\Facades\Cookie;
use LaraGram\Support\Facades\Event;
use LaraGram\Support\Facades\Route;
use LaraGram\Support\ServiceProvider;

class CitadelServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        config([
            'auth.guards.citadel' => array_merge([
                'driver' => 'citadel',
                'provider' => null,
            ], config('auth.guards.citadel', [])),
        ]);

        if (! $this->app->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__.'/../config/citadel.php', 'citadel');
        }

        $this->app->when([
            AuthorizationController::class,
            DeviceAuthorizationController::class,
        ])->needs(StatefulGuard::class)->give(fn () => Auth::guard(config('citadel.oauth.guard')));

        $this->app->when(TelegramLoginController::class)
            ->needs(StatefulGuard::class)
            ->give(fn () => Auth::guard(config('citadel.telegram.login_guard')));

        $this->app->singleton(ClientRepository::class);
        $this->app->singleton(TokenRepository::class);

        $this->registerResponseBindings();
        $this->registerTelegramAuthenticator();
        $this->registerAuthorizationServer();
        $this->registerResourceServer();
        $this->registerGuard();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerCommands();

        if (static::runningBotUpdate()) {
            return;
        }

        $this->loadViewsFrom(__DIR__.'/../resources/views', 'citadel');

        $this->registerRoutes();
        $this->registerMiddleware();
        $this->deleteCookieOnLogout();
    }

    /**
     * Register the Citadel routes.
     */
    protected function registerRoutes(): void
    {
        if (! Citadel::$registersRoutes || $this->app->routesAreCached()) {
            return;
        }

        Route::group([
            'as' => 'citadel.',
            'prefix' => config('citadel.oauth.path', 'oauth'),
            'middleware' => config('citadel.oauth.middleware', []),
        ], function (): void {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        });

        Route::get('/citadel/csrf-cookie', [CsrfCookieController::class, 'show'])
            ->middleware('web')
            ->name('citadel.csrf-cookie');

        if (Citadel::$registersMetadataRoute) {
            Route::get('/.well-known/oauth-authorization-server', AuthorizationServerMetadataController::class)
                ->name('citadel.metadata');
        }
    }

    /**
     * Register the middleware aliases and priority.
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        foreach (['abilities' => CheckAbilities::class, 'ability' => CheckForAnyAbility::class] as $alias => $middleware) {
            if (! array_key_exists($alias, $router->getMiddleware())) {
                $router->aliasMiddleware($alias, $middleware);
            }
        }

        if ($this->app->bound(\LaraGram\Contracts\Http\Kernel::class)) {
            $kernel = $this->app->make(\LaraGram\Contracts\Http\Kernel::class);

            if (method_exists($kernel, 'prependToMiddlewarePriority')) {
                $kernel->prependToMiddlewarePriority(EnsureFrontendRequestsAreStateful::class);
            }
        }
    }

    /**
     * Register the package's publishable resources.
     */
    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], 'citadel-migrations');

        $this->publishes([
            __DIR__.'/../config/citadel.php' => config_path('citadel.php'),
        ], 'citadel-config');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/citadel'),
        ], 'citadel-views');
    }

    /**
     * Register the Citadel commands.
     */
    protected function registerCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            Console\InstallCommand::class,
            Console\ClientCommand::class,
            Console\HashCommand::class,
            Console\KeysCommand::class,
            Console\PurgeCommand::class,
        ]);
    }

    /**
     * Register the response bindings.
     */
    protected function registerResponseBindings(): void
    {
        $this->app->singleton(ApprovedDeviceAuthorizationResponseContract::class, ApprovedDeviceAuthorizationResponse::class);
        $this->app->singleton(DeniedDeviceAuthorizationResponseContract::class, DeniedDeviceAuthorizationResponse::class);

        $this->app->singleton(AuthorizationViewResponse::class, fn () => new SimpleViewResponse('citadel::authorize'));
        $this->app->singleton(DeviceAuthorizationViewResponse::class, fn () => new SimpleViewResponse('citadel::device.authorize'));
        $this->app->singleton(DeviceUserCodeViewResponse::class, fn () => new SimpleViewResponse('citadel::device.user-code'));
    }

    /**
     * Register the verifier of Telegram payloads.
     */
    protected function registerTelegramAuthenticator(): void
    {
        $this->app->singleton(TelegramAuthenticator::class, function ($app) {
            $config = $app['config']->get('citadel.telegram', []);

            $keys = $config['public_keys'] ?? [];

            return new TelegramAuthenticator(
                botToken: Citadel::botConnection()['token'] ?? null,
                ttl: (int) ($config['auth_ttl'] ?? 86400),
                scheme: $config['scheme'] ?? 'hmac',
                publicKey: ($config['test_env'] ?? false) ? ($keys['test'] ?? null) : ($keys['production'] ?? null),
            );
        });
    }

    /**
     * Register the authorization server.
     */
    protected function registerAuthorizationServer(): void
    {
        $this->app->singleton(AuthorizationServer::class, function ($app) {
            $server = new AuthorizationServer(
                $app->make(ClientRepository::class),
                $this->makeCryptKey('private'),
                $this->makeTokenEncrypter(),
                $app['events'],
            );

            $server->setDefaultScope(Citadel::$defaultScope);
            $server->revokeRefreshTokens(Citadel::$revokeRefreshTokenAfterUse);

            $refreshTTL = Citadel::refreshTokensExpireIn();

            $server->enableGrantType(
                (new AuthCodeGrant(new DateInterval('PT10M')))->setRefreshTokenTTL($refreshTTL), Citadel::tokensExpireIn()
            );

            $server->enableGrantType(
                (new RefreshTokenGrant)->setRefreshTokenTTL($refreshTTL), Citadel::tokensExpireIn()
            );

            $server->enableGrantType(new ClientCredentialsGrant, Citadel::clientCredentialsTokensExpireIn());

            if (Citadel::$passwordGrantEnabled) {
                $server->enableGrantType((new PasswordGrant)->setRefreshTokenTTL($refreshTTL), Citadel::tokensExpireIn());
            }

            if (Citadel::$implicitGrantEnabled) {
                $server->enableGrantType(new ImplicitGrant, Citadel::tokensExpireIn());
            }

            if (Citadel::$deviceCodeGrantEnabled) {
                $server->enableGrantType(
                    (new DeviceCodeGrant(new DateInterval('PT10M'), $this->deviceVerificationUri()))->setRefreshTokenTTL($refreshTTL),
                    Citadel::tokensExpireIn()
                );
            }

            if (Citadel::$telegramGrantEnabled) {
                foreach ([TelegramGrant::INIT_DATA, TelegramGrant::LOGIN_WIDGET] as $type) {
                    $server->enableGrantType(
                        (new TelegramGrant($app->make(TelegramAuthenticator::class), $type))->setRefreshTokenTTL($refreshTTL),
                        Citadel::tokensExpireIn()
                    );
                }
            }

            return $server;
        });
    }

    /**
     * Get the URI of the device verification page.
     */
    protected function deviceVerificationUri(): string
    {
        return Route::has('citadel.device')
            ? route('citadel.device')
            : url(trim(config('citadel.oauth.path', 'oauth'), '/').'/device');
    }

    /**
     * Register the resource server.
     */
    protected function registerResourceServer(): void
    {
        $this->app->singleton(ResourceServer::class, fn () => new ResourceServer($this->makeCryptKey('public')));
    }

    /**
     * Create a CryptKey instance.
     */
    protected function makeCryptKey(string $type): CryptKey
    {
        $key = str_replace('\\n', "\n", config("citadel.oauth.{$type}_key") ?? '');

        if (! $key) {
            $key = 'file://'.Citadel::keyPath('oauth-'.$type.'.key');
        }

        return new CryptKey($key, null, Citadel::$validateKeyPermissions);
    }

    /**
     * Create the encrypter of authorization codes, refresh tokens and device codes.
     */
    protected function makeTokenEncrypter(): Encrypter
    {
        $key = Citadel::tokenEncryptionKey($this->app->make('encrypter'));

        $cipher = strlen($key) === 16 ? 'aes-128-cbc' : 'aes-256-cbc';

        return new Encrypter(strlen($key) === 16 || strlen($key) === 32 ? $key : hash('sha256', $key, true), $cipher);
    }

    /**
     * Register the "citadel" guard driver.
     */
    protected function registerGuard(): void
    {
        $provider = $this;

        Auth::resolved(function ($auth) use ($provider): void {
            $auth->extend('citadel', function ($app, $name, array $config) use ($auth, $provider) {
                return tap($provider->makeGuard($auth, $name, $config), function ($guard): void {
                    app()->refresh('http.request', $guard, 'setRequest');
                });
            });
        });
    }

    /**
     * Make an instance of the guard.
     *
     * @param  \LaraGram\Auth\AuthManager  $auth
     * @param  array<string, mixed>  $config
     */
    public function makeGuard($auth, string $name, array $config): Guard
    {
        $provider = $config['provider'] ?? null;

        return new Guard(
            $name,
            $auth,
            $this->app->make(ResourceServer::class),
            $this->app->make(ClientRepository::class),
            $this->app->make('encrypter'),
            $this->app->make('http.request'),
            $provider ? $auth->createUserProvider($provider) : null,
            $provider,
            config('citadel.expiration'),
            (bool) config('citadel.last_used_at', true),
        );
    }

    /**
     * Register the cookie deletion on logout.
     */
    protected function deleteCookieOnLogout(): void
    {
        Event::listen(Logout::class, function (): void {
            $request = $this->app['http.request'];

            if ($request instanceof \LaraGram\Http\Request && $request->hasCookie(Citadel::cookie())) {
                Cookie::queue(Cookie::forget(Citadel::cookie()));
            }
        });
    }

    /**
     * Determine if the application is handling a single bot update (no HTTP routes needed).
     */
    public static function runningBotUpdate(): bool
    {
        $payload = $_SERVER['argv'][1] ?? null;

        return is_string($payload)
            && str_starts_with(ltrim($payload), '{')
            && str_contains($payload, 'update_id');
    }
}
