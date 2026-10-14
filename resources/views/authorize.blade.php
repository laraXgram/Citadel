@extends('citadel::layout')

@section('title', 'Authorization Request')

@section('content')
    <h1>Authorization Request</h1>

    <p><strong>{{ $client->name }}</strong> is requesting permission to access your account.</p>

    @if (count($scopes) > 0)
        <p>This application will be able to:</p>

        <ul>
            @foreach ($scopes as $scope)
                <li>{{ $scope->description }}</li>
            @endforeach
        </ul>
    @endif

    <div class="actions">
        <form method="post" action="{{ route('citadel.authorizations.deny') }}">
            @csrf
            @method('DELETE')
            <input type="hidden" name="state" value="{{ $request->state }}">
            <input type="hidden" name="client_id" value="{{ $client->getKey() }}">
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit">Cancel</button>
        </form>

        <form method="post" action="{{ route('citadel.authorizations.approve') }}">
            @csrf
            <input type="hidden" name="state" value="{{ $request->state }}">
            <input type="hidden" name="client_id" value="{{ $client->getKey() }}">
            <input type="hidden" name="auth_token" value="{{ $authToken }}">
            <button type="submit" class="primary">Authorize</button>
        </form>
    </div>
@endsection
