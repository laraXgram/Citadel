@extends('citadel::layout')

@section('title', 'Authorize Device')

@section('content')
    <h1>Authorize Device</h1>

    <p><strong>{{ $client->name }}</strong> is requesting permission to access your account.</p>

    @if (count($scopes) > 0)
        <p>This device will be able to:</p>

        <ul>
            @foreach ($scopes as $scope)
                <li>{{ $scope->description }}</li>
            @endforeach
        </ul>
    @endif

    <div class="actions">
        <form method="post" action="{{ route('citadel.device.authorizations.deny') }}">
            @csrf
            @method('DELETE')
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Deny</button>
        </form>

        <form method="post" action="{{ route('citadel.device.authorizations.approve') }}">
            @csrf
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit" class="primary">Approve</button>
        </form>
    </div>

    @if ($telegramUri ?? null)
        <p class="muted">You can also <a href="{{ $telegramUri }}">approve this device in Telegram</a>.</p>
    @endif
@endsection
