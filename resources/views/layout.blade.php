<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name') }} - @yield('title')</title>
    <style>
        :root { --bg: #f4f6f8; --card: #fff; --text: #17212b; --muted: #6b7a89; --accent: #2aabee; --danger: #e53935; --border: #e3e8ee; }
        @media (prefers-color-scheme: dark) { :root { --bg: #0e1621; --card: #17212b; --text: #f5f5f5; --muted: #8b9aa7; --border: #2b3946; } }
        * { box-sizing: border-box; }
        body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px; background: var(--bg); color: var(--text); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 24px; }
        h1 { font-size: 20px; margin: 0 0 8px; }
        p, li { color: var(--muted); }
        ul { padding-left: 20px; }
        .actions { display: flex; gap: 12px; margin-top: 20px; }
        .actions form { flex: 1; }
        button, .button { width: 100%; display: inline-block; text-align: center; text-decoration: none; padding: 10px 14px; border-radius: 10px; border: 1px solid var(--border); background: transparent; color: var(--text); font-size: 15px; cursor: pointer; }
        .primary { background: var(--accent); border-color: var(--accent); color: #fff; }
        input { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: transparent; color: var(--text); font-size: 18px; letter-spacing: 2px; text-transform: uppercase; text-align: center; }
        .error { color: var(--danger); }
        .status { padding: 10px 12px; border-radius: 10px; background: rgba(42, 171, 238, .12); }
        .muted { color: var(--muted); font-size: 13px; }
        a { color: var(--accent); }
    </style>
</head>
<body>
    <main class="card">
        @yield('content')
    </main>
</body>
</html>
