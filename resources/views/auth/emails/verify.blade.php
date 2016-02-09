Hello, {{ $username }}!

<br>

Thank you for registering! Please follow the link below to verify your email address.

<br>

<a href="{{ $link = url('register/verify', $token) }}">{{ $link }}</a>.