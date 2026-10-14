<?php

namespace LaraGram\Citadel\Telegram;

use LaraGram\Citadel\Citadel;
use LaraGram\Citadel\DeviceCode;
use LaraGram\Citadel\OAuth\AuthorizationServer;
use LaraGram\Citadel\OAuth\OAuthServerException;
use LaraGram\Contracts\Auth\Authenticatable;
use LaraGram\Request\Request as BotRequest;

/**
 * Lets users approve or deny a device (RFC 8628) inside the bot instead of
 * on the web verification page.
 *
 * The device's "verification_uri_telegram" link opens the bot with
 * "/start device-ABCDEFGH"; users may also send "/device ABCD-EFGH".
 *
 *     Citadel::botListeners();
 */
class ApproveDevice
{
    /**
     * The callback data prefix of the approval buttons.
     */
    public const CALLBACK_PREFIX = 'citadel:device:';

    /**
     * The auth guard that resolves the Telegram user's account.
     */
    public static string $guard = 'bot';

    /**
     * Create a new listener instance.
     */
    public function __construct(
        protected AuthorizationServer $server,
    ) {
    }

    /**
     * Show the device request with "Approve" and "Deny" buttons.
     */
    public function prompt(BotRequest $request, ?string $code = null): void
    {
        $chat = $request->message->chat ?? null;

        if ($chat === null) {
            return;
        }

        if (($chat->type ?? null) !== 'private') {
            $this->send($request, $chat->id, 'For your security, devices can only be approved in a private chat with the bot.');

            return;
        }

        if (! $this->user()) {
            $this->send($request, $chat->id, 'Your account is not registered, so this device cannot be approved.');

            return;
        }

        if (blank($code)) {
            $this->send($request, $chat->id, 'Send the code shown on your device, for example: /device ABCD-EFGH');

            return;
        }

        $deviceCode = $this->server->findPendingDeviceCode($code);

        if (! $deviceCode) {
            $this->send($request, $chat->id, 'This code is invalid or has expired. Request a new code on your device.');

            return;
        }

        $this->send($request, $chat->id, $this->describe($deviceCode), [
            'parse_mode' => 'HTML',
            'reply_markup' => json_encode(['inline_keyboard' => [[
                ['text' => 'Approve', 'callback_data' => static::CALLBACK_PREFIX.'approve:'.$deviceCode->user_code],
                ['text' => 'Deny', 'callback_data' => static::CALLBACK_PREFIX.'deny:'.$deviceCode->user_code],
            ]]]),
        ]);
    }

    /**
     * Record the user's decision from the inline buttons.
     */
    public function decide(BotRequest $request, string $decision, string $code): void
    {
        $query = $request->callback_query ?? null;

        if ($query === null) {
            return;
        }

        $message = $query->message ?? null;

        if (($message->chat->type ?? null) !== 'private' || ! $user = $this->user()) {
            $this->answer($request, $query->id, 'You cannot approve this device.');

            return;
        }

        $deviceCode = $this->server->findPendingDeviceCode($code);

        if (! $deviceCode) {
            $this->answer($request, $query->id, 'This code is invalid or has expired.');
            $this->edit($request, $message, 'This device request has expired or was already answered.');

            return;
        }

        $approved = $decision === 'approve';

        try {
            $this->server->completeDeviceAuthorizationRequest($deviceCode, $user->getAuthIdentifier(), $approved);
        } catch (OAuthServerException) {
            $this->answer($request, $query->id, 'This code is invalid or has expired.');

            return;
        }

        $client = e($deviceCode->client?->name ?? 'The device');

        $this->answer($request, $query->id, $approved ? 'Device approved.' : 'Device denied.');
        $this->edit($request, $message, $approved
            ? "✅ <b>{$client}</b> can now access your account. You may return to your device."
            : "🚫 <b>{$client}</b> was denied access to your account.");
    }

    /**
     * Describe the device request for the user.
     */
    protected function describe(DeviceCode $deviceCode): string
    {
        $lines = [
            '<b>'.e($deviceCode->client?->name ?? 'A device').'</b> is requesting access to your account.',
            '',
            'Code: <code>'.e($deviceCode->formattedUserCode()).'</code>',
        ];

        $scopes = Citadel::scopesFor((array) $deviceCode->scopes);

        if ($scopes !== []) {
            $lines[] = '';
            $lines[] = 'It will be able to:';

            foreach ($scopes as $scope) {
                $lines[] = '• '.e($scope->description);
            }
        }

        $lines[] = '';
        $lines[] = 'Only approve if the same code is shown on a device you are signing in to.';

        return implode("\n", $lines);
    }

    /**
     * Resolve the account of the Telegram user.
     */
    protected function user(): ?Authenticatable
    {
        return app('auth')->guard(static::$guard)->user();
    }

    /**
     * Send a message to the chat.
     *
     * @param  array<string, mixed>  $parameters
     */
    protected function send(BotRequest $request, int|string $chatId, string $text, array $parameters = []): void
    {
        $request->call('sendMessage', ['chat_id' => $chatId, 'text' => $text, ...$parameters]);
    }

    /**
     * Answer the callback query.
     */
    protected function answer(BotRequest $request, string $queryId, string $text): void
    {
        $request->call('answerCallbackQuery', ['callback_query_id' => $queryId, 'text' => $text]);
    }

    /**
     * Replace the prompt with the outcome, removing the buttons.
     */
    protected function edit(BotRequest $request, mixed $message, string $text): void
    {
        if (! isset($message->chat->id, $message->message_id)) {
            return;
        }

        $request->call('editMessageText', [
            'chat_id' => $message->chat->id,
            'message_id' => $message->message_id,
            'text' => $text,
            'parse_mode' => 'HTML',
        ]);
    }
}
