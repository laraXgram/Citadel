@extends('citadel::layout')

@section('title', 'Log in with Telegram')

@section('content')
    <h1>Log in</h1>

    <p>Continue with your Telegram account.</p>

    @error('telegram')
        <p class="error">{{ $message }}</p>
    @enderror

    @if ($botUsername)
        <script async src="https://telegram.org/js/telegram-widget.js?22"
                data-telegram-login="{{ $botUsername }}"
                data-size="large"
                data-radius="10"
                data-auth-url="{{ $callbackUrl }}"
                data-request-access="write"></script>
    @else
        <p class="error">The bot username is not configured (bot.connections.*.username).</p>
    @endif
@endsection
