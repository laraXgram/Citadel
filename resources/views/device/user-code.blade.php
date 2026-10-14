@extends('citadel::layout')

@section('title', 'Connect a Device')

@section('content')
    <h1>Connect a Device</h1>

    @if (session('status') === 'authorization-approved')
        <p class="status">Success! Continue on your device.</p>
    @elseif (session('status') === 'authorization-denied')
        <p class="status">Denied! The device was not connected.</p>
    @else
        <p>Enter the code displayed on your device.</p>
    @endif

    <form method="get" action="{{ route('citadel.device.authorizations.authorize') }}">
        <input type="text" name="user_code" value="{{ old('user_code') }}" placeholder="ABCD-EFGH" autocomplete="off" autofocus required>

        @error('user_code')
            <p class="error">{{ $message }}</p>
        @enderror

        <div class="actions">
            <button type="submit" class="primary">Continue</button>
        </div>
    </form>
@endsection
