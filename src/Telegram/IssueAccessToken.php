<?php

namespace LaraGram\Citadel\Telegram;

use LaraGram\Request\Request as BotRequest;
use LaraGram\Support\Tempora;

/**
 * A bot listener that issues and revokes personal access tokens from a private
 * chat, so users authenticate API clients (and MCP clients) with their Telegram identity.
 *
 *     IssueAccessToken::using('token', abilities: ['orders:read'], expiresInMinutes: 60 * 24 * 30);
 *
 *     Bot::onCommand('token {action?}', IssueAccessToken::class);
 *
 * "/token" issues a new token and "/token revoke" deletes every token issued this way.
 * The user model must use Citadel's HasApiTokens trait.
 */
class IssueAccessToken
{
    /**
     * The name of the issued tokens.
     */
    protected static string $tokenName = 'telegram';

    /**
     * The abilities of the issued tokens.
     *
     * @var string[]
     */
    protected static array $abilities = ['*'];

    /**
     * The lifetime of the issued tokens in minutes (null for no expiry).
     */
    protected static ?int $expiresInMinutes = null;

    /**
     * The auth guard that resolves the Telegram user's account.
     */
    protected static string $guard = 'bot';

    /**
     * Configure the issued tokens.
     *
     * @param  string[]  $abilities
     */
    public static function using(string $name = 'telegram', array $abilities = ['*'], ?int $expiresInMinutes = null, string $guard = 'bot'): void
    {
        static::$tokenName = $name;
        static::$abilities = $abilities;
        static::$expiresInMinutes = $expiresInMinutes;
        static::$guard = $guard;
    }

    /**
     * Handle the command.
     */
    public function __invoke(BotRequest $request): void
    {
        $chat = $request->message->chat ?? null;

        if ($chat === null) {
            return;
        }

        if (($chat->type ?? null) !== 'private') {
            $this->reply($request, $chat->id, 'For your security, access tokens are only issued in a private chat with the bot.');

            return;
        }

        $user = app('auth')->guard(static::$guard)->user();

        if ($user === null || ! method_exists($user, 'createToken')) {
            $this->reply($request, $chat->id, 'Your account is not registered, so an access token cannot be issued.');

            return;
        }

        if ($this->action($request) === 'revoke') {
            $revoked = $user->tokens()->where('name', static::$tokenName)->delete();

            $this->reply($request, $chat->id, "Revoked {$revoked} access token(s).");

            return;
        }

        $expiresAt = static::$expiresInMinutes !== null ? Tempora::now()->addMinutes(static::$expiresInMinutes) : null;

        $token = $user->createToken(static::$tokenName, static::$abilities, $expiresAt)->plainTextToken;

        $lines = [
            'Your access token:',
            '',
            '<code>'.htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE).'</code>',
            '',
            'Use it as a Bearer token in your client. It is shown only once; delete this message after copying it.',
        ];

        if ($expiresAt !== null) {
            $lines[] = 'Expires at: '.$expiresAt->toDateTimeString().' UTC.';
        }

        $this->reply($request, $chat->id, implode("\n", $lines), ['parse_mode' => 'HTML', 'protect_content' => true]);
    }

    /**
     * Get the requested action ("revoke" or empty).
     */
    protected function action(BotRequest $request): string
    {
        $parts = preg_split('/\s+/', trim((string) ($request->message->text ?? '')), 2) ?: [];

        return strtolower(trim($parts[1] ?? ''));
    }

    /**
     * Send a message to the chat.
     *
     * @param  array<string, mixed>  $parameters
     */
    protected function reply(BotRequest $request, int|string $chatId, string $text, array $parameters = []): void
    {
        $request->call('sendMessage', ['chat_id' => $chatId, 'text' => $text, ...$parameters]);
    }
}
