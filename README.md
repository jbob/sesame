# Sesame

Web-based password storage written with Perl/Mojolicious/MongoDB/Manel. See it
in action at [https://sesame.markusko.ch](https://sesame.markusko.ch)

## Dependencies

* Perl
* Mojolicious
* Mango module (Non-blocking MongoDB driver for Perl)
* Mandel (ORM module for Mango/MongoDB)
* MongoDB

## Installation

Simply clone or download the the repository, adjust the sesame.conf file and
execute either:

    $ morbo script/pastr (for development), or
    $ hypnotoad script/pastr (for production)

The app will then listen on either 127.0.0.1:3000 (development) or 0.0.0.0:8012
(production).

To access your app via a reverse proxy, create a minimal VHost like this:

    <VirtualHost *:80>
        ServerName pastr.markusko.ch
        ProxyPass / http://127.0.0.1:8012/
    </VirtualHost>
