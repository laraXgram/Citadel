<?php

namespace LaraGram\Citadel\Console;

use LaraGram\Citadel\Citadel;
use LaraGram\Console\Attribute\AsCommand;
use LaraGram\Console\Command;
use LaraGram\Database\Eloquent\Builder;
use LaraGram\Support\Facades\Date;

#[AsCommand(name: 'citadel:purge')]
class PurgeCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'citadel:purge
                            {--revoked : Only purge revoked tokens and authentication codes}
                            {--expired : Only purge expired tokens and authentication codes}
                            {--hours=168 : The number of hours to retain expired tokens}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Purge revoked and / or expired personal access tokens, OAuth tokens and codes';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $revoked = $this->option('revoked') || ! $this->option('expired');

        $expired = $this->option('expired') || ! $this->option('revoked')
            ? Date::now()->subHours((int) $this->option('hours'))
            : false;

        $now = Date::now();

        $constraint = fn (Builder $query): Builder => $query
            ->when($revoked, fn () => $query->orWhere('revoked', true))
            ->when($expired, fn () => $query->orWhere('expires_at', '<', $expired));

        if ($expired) {
            $model = Citadel::personalAccessTokenModel();

            $model::where('expires_at', '<', $expired)->delete();

            if ($minutes = config('citadel.expiration')) {
                $model::where('created_at', '<', $expired->copy()->subMinutes($minutes))->delete();
            }
        }

        Citadel::token()->newQuery()
            ->where($constraint)
            ->whereDoesntHave('refreshToken', fn (Builder $query): Builder => $query
                ->where('revoked', false)
                ->where(fn (Builder $query): Builder => $query
                    ->whereNull('expires_at')
                    ->orWhere('expires_at', '>', $now)))
            ->delete();

        Citadel::authCode()->newQuery()->where($constraint)->delete();
        Citadel::refreshToken()->newQuery()->where($constraint)->delete();
        Citadel::deviceCode()->newQuery()->where($constraint)->delete();

        $this->components->info(sprintf('Purged %s.', implode(' and ', array_filter([
            $revoked ? 'revoked items' : null,
            $expired ? "items expired for more than {$expired->longAbsoluteDiffForHumans()}" : null,
        ]))));
    }
}
