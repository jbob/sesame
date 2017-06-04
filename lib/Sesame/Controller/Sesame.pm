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
        $self->session(password => sha512_hex sha512_hex encode('UTF-8', $username.$password));
        return $self->redirect_to($self->session('target') // '/');
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
    $self->session(username => '');
    $self->session(password => '');
    $self->session(key => '');
    return $self->redirect_to('index');
}

sub register {
    my $self = shift;
    my $username  = $self->param('username')  // '';
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
            return $self->redirect_to('register');
        } else {
            my $password = sha512_hex sha512_hex encode('UTF-8', $username . $password1);
            my $tfa_secret = encode_base32(entropy_source->get_bits(50*8));
            my $plain_key = encode_base32(entropy_source->get_bits(50*8));
            my $enc_key = $self->encrypt($password, $plain_key);
            my $url = sprintf('otpauth://totp/%s?secret=%s', "Sesame-$username", $tfa_secret);
            my $qr_url = sprintf('https://chart.googleapis.com/chart?chs=400x400&chld=M|0&cht=qr&chl=%s', uri_escape_utf8($url));
            $self->users->create({ username   => $username,
                                   password   => $password,
                                   tfa_secret => $tfa_secret,
                                   key        => $enc_key})->save(sub {
                                       my ($users, $err, $user) = @_;
                                       $self->reply->exception($err) if $err;
                                       $self->render(tfa_secret => $tfa_secret,
                                                     qr_url     => $qr_url);
                                   });
        }
    });
    $self->render_later;
}

sub changepw {
    my $self = shift;
    my $old_password  = $self->param('old_password')  // '';
    my $new_password1 = $self->param('new_password1') // '';
    my $new_password2 = $self->param('new_password2') // '';

    if ($self->req->method eq 'GET') {
        return $self->render;
    }
    if (not $old_password or not $new_password1 or not $new_password2) {
        $self->flash(msg => 'Please fill the complete form', type => 'danger');
        return $self->redirect_to('changepw');
    }
    if ($new_password1 ne $new_password2) {
        $self->flash(msg => 'Passwords do not match', type => 'danger');
        return $self->redirect_to('changepw');
    }

    my $username = $self->session('username');
    $old_password = sha512_hex sha512_hex encode('UTF8', $username.$old_password);

    $self->users->search({ username => $username, password => $old_password })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        if ($user) {
            $user->password(sha512_hex sha512_hex encode('UTF8', $username.$new_password1));
            $user->key($self->encrypt($user->password, $self->session('key')));
            $user->save;
            return $self->redirect_to('logout');
        } else {
            $self->flash(msg => 'Old password is incorrect', type => 'danger');
            return $self->redirect_to('changepw');
        }

    });
    $self->render_later;
}

sub deleteacc {
    my $self = shift;

    if ($self->req->method eq 'GET') {
        return $self->render;
    }

    my $confirmation = $self->param('confirmation') // '';
    if ($confirmation eq 'YES') {
        my $username = $self->session('username');
        $self->users->search({ username => $username })->single(sub {
            my ($users, $err, $user) = @_;
            $self->reply->exception($err) if $err;
            my $logins = $user->logins;
            for my $login (@$logins) {
                $login->remove;
            }
            $user->remove;
            $self->redirect_to('logout');
        });
    } else {
        $self->redirect_to('account');
    }


    $self->render_later;
}

sub logins_list {
    my $self = shift;
    my $username = $self->session('username');
    my $key      = $self->session('key');

    $self->users->search({ username => $username })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        my $logins = $user->logins;
        for my $login(@$logins) {
            $login->page(decode('UTF-8', $self->decrypt($key, $login->page)));
            $login->login(decode('UTF-8', $self->decrypt($key, $login->login)));
            $login->password(decode('UTF-8', $self->decrypt($key, $login->password)));
            $login->comment(decode('UTF-8', $self->decrypt($key, $login->comment)));
        }
        $self->render(logins => $logins);
    });
    $self->render_later;
}

sub upsert {
    my $self = shift;
    my $stash = $self->stash;
    my $username = $self->session('username');
    my $key      = $self->session('key');
    my $id       = $self->req->param('id') || $stash->{id};
    my $page     = $self->encrypt($key, $self->req->param('page') // '');
    my $login    = $self->encrypt($key, $self->req->param('login') // '');
    my $password = $self->encrypt($key, $self->req->param('password') // '');
    my $comment  = $self->encrypt($key, $self->req->param('comment') // '');

    if ($id) {
        # Update existing record
        $self->users->search({ username => $username })->single(sub {
            my ($users, $err, $user) = @_;
            $self->reply->exception($err) if $err;
            $self->logins->search({'user.$id' => bson_oid($user->id), _id => bson_oid($id)})->single(sub {
                my ($logins, $err, $l) = @_;
                $self->reply->exception($err) if $err;
                $l->page($page);
                $l->login($login);
                $l->password($password);
                $l->comment($comment);
                $l->save;
                $self->redirect_to('logins');
            });
        });
    } else {
        # Create new record
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
    }

    $self->render_later;
}

sub edit {
    my $self = shift;
    my $stash = $self->stash;
    my $username = $self->session('username');
    my $key = $self->session('key');
    my $id = $self->req->param('id') || $stash->{id};
    $self->users->search({ username => $username })->single(sub {
        my ($users, $err, $user) = @_;
        $self->reply->exception($err) if $err;
        $self->logins->search({'user.$id' => bson_oid($user->id), _id => bson_oid($id)})->single(sub {
            my ($logins, $err, $login) = @_;
            $self->reply->exception($err) if $err;
            $self->stash(id       => $id);
            $self->stash(page     => decode('UTF-8', $self->decrypt($key, $login->page)));
            $self->stash(login    => decode('UTF_8', $self->decrypt($key, $login->password)));
            $self->stash(password => decode('UTF-8', $self->decrypt($key, $login->password)));
            $self->stash(comment  => decode('UTF-8', $self->decrypt($key, $login->comment)));
            $self->render('sesame/form');
        });
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
