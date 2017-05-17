package Sesame::Controller::Sesame;
use Mojo::Base 'Mojolicious::Controller';

use Digest::SHA qw(sha512_hex);
use Data::Entropy qw(entropy_source);
use Convert::Base32;
use URI::Escape;
use Mango::BSON 'bson_oid';
use Crypt::CBC;
use Encode qw(decode encode);

sub login {
    my $self = shift;
    my $stash = $self->stash;
    my $config = $stash->{config};

    my $username = $self->param('username') // '';
    my $password = $self->param('password') // '';
    my $tfa_token = $self->param('tfa_token') // '';
    if ($username and $password and $tfa_token)  {
        $self->session(username => $username);
        $self->session(tfa_token => $tfa_token);
        $self->session(key => sha512_hex encode('UTF-8', $username . $password));
        $self->session(password => sha512_hex $self->session('key'));
        $self->redirect_to($self->session('target') // '/');
    } else {
        if ($self->req->method eq 'POST') {
            $self->flash(msg => 'Please fill the complete form', type => 'danger');
            return $self->redirect_to('login');
        }
    }
}

sub logout {
    my $self = shift;
    $self->session(logged_in => 0);
    $self->session('username' => '');
    $self->session('password' => '');
    $self->session(key => '');
    $self->redirect_to('/');
}

sub register {
    my $self = shift;
    my $username = $self->param('username') // '';
    my $password1 = $self->param('password1') // '';
    my $password2 = $self->param('password2') // '';


    if ($self->req->method eq 'GET') {
        return $self->render;
    }

    if (not $username or not $password1 or not $password2) {
        $self->flash(msg => 'Please fill the complete form', type => 'danger');
        return $self->redirect_to('register');
    }
    if ($password1 ne $password2) {
        $self->flash(msg => 'Passwords do not match', type => 'danger');
        return $self->redirect_to('register');
    }

    $self->users->search({ username => $username })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        if ($user) {
            $self->flash(msg => 'Username already taken', type => 'danger');
            $self->redirect_to('register');
        } else {
            my $password = sha512_hex sha512_hex encode('UTF-8', $username . $password1);
            my $tfa_secret = encode_base32(entropy_source->get_bits(50*8));
            my $url = sprintf('otpauth://totp/%s?secret=%s', 'Sesame', $tfa_secret);
            my $qr_url = sprintf('https://chart.googleapis.com/chart?chs=400x400&chld=M|0&cht=qr&chl=%s', uri_escape($url));
            $self->users->create({ username => $username,
                                   password => $password,
                                   tfa_secret => $tfa_secret})->save(sub {
                                       my ($users, $err, $user) = @_;
                                       $self->reply->exception($err) if $err;
                                       $self->render(tfa_secret => $tfa_secret,
                                                     qr_url     => $qr_url);
                                   });
        }
    });
    $self->render_later;
}

sub logins_list {
    my $self = shift;
    my $username = $self->session('username');
    my $key      = $self->session('key');
    my $cipher   = Crypt::CBC->new( -key => $key, -cipher => 'Blowfish');

        warn "CALLED1";
    $self->users->search({ username => $username })->single(sub {
        warn "CALLED";
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        my $logins = $user->logins;
        for my $login(@$logins) {
            $login->page(decode('UTF-8', $cipher->decrypt_hex($login->page)));
            $login->login(decode('UTF-8', $cipher->decrypt_hex($login->login)));
            $login->password(decode('UTF-8', $cipher->decrypt_hex($login->password)));
            $login->comment(decode('UTF-8', $cipher->decrypt_hex($login->comment)));
        }
        $self->render(logins => $logins);
    });
        warn "CALLED2";
    $self->render_later;
}

sub create {
    my $self = shift;
    my $username = $self->session('username');
    my $key      = $self->session('key');
    my $cipher   = Crypt::CBC->new( -key => $key, -cipher => 'Blowfish');
    my $page     = $cipher->encrypt_hex($self->req->param('page') // '');
    my $login    = $cipher->encrypt_hex($self->req->param('login') // '');
    my $password = $cipher->encrypt_hex($self->req->param('password') // '');
    my $comment  = $cipher->encrypt_hex($self->req->param('comment') // '');

    my $newlogin = $self->logins->create({ page     => $page,
                                           login    => $login,
                                           password => $password,
                                           comment  => $comment });

    $self->users->search({ username => $username })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        $user->add_logins($newlogin);
        $self->redirect_to('logins');
    });

    $self->render_later;
}

sub delete {
    my $self = shift;
    my $stash = $self->stash;
    my $id = $self->req->param('id') || $stash->{id};
    my $username = $self->session('username');

    $self->users->search({ username => $username })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        $self->logins->search({'user.$id' => bson_oid($user->id), _id => bson_oid($id)})->single(sub {
            my ($logins, $err, $login) = @_;
            $self->reply->exception($err) if $err;
            $login->remove;
            $self->redirect_to('logins');
        });
    });

    $self->render_later;
}

1;
