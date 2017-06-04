package Sesame::Helpers;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::IOLoop;

use Authen::OATH;
use Convert::Base32;
use Encode qw(decode encode);
use Crypt::CBC;

sub make_token_6 {
    my $token = shift;
    while (length $token < 6) {
        $token = "0$token";
    }
    return $token;
}

sub register {
    my ($self, $app) = @_;

    $app->helper(model => sub {
        state $model = Sesame::Model->connect($app->config->{mongouri});
    });

    $app->helper(users => sub { $_[0]->app->model->collection('user') } );
    $app->helper(logins => sub { $_[0]->app->model->collection('login') } );

    $app->helper(encrypt => sub {
        my $self = shift;
        my $key  = shift;
        my $text = shift;

        my $cipher = Crypt::CBC->new(-key => $key, -cipher => 'Blowfish');
        return $cipher->encrypt_hex($text);
    });

    $app->helper(decrypt => sub {
        my $self = shift;
        my $key  = shift;
        my $text = shift;

        my $cipher = Crypt::CBC->new(-key => $key, -cipher => 'Blowfish');
        return $cipher->decrypt_hex($text);
    });

    $app->helper(auth => sub {
        my $self = shift;
        return 1 if $self->session
                  and $self->session('logged_in')
                  and $self->session('logged_in') == 1;
        if (not $self->session('username')) {
            $self->session(logged_in => 0);
            $self->session(target => $self->req->url->to_abs->path);
            $self->redirect_to('/login');
            return 0;
        }

        my $username = $self->session('username');
        my $password = $self->session('password');
        my $user = $app->users->search({ username => $username, password => $password })->single;

        if ($user) {
            my $tfa_secret = decode_base32 $user->tfa_secret;
            my $key        = $self->decrypt($password, $user->key);
            my $correct_token = make_token_6(Authen::OATH->new->totp($tfa_secret));
            my $tfa_token = $self->session('tfa_token');
            if ($correct_token eq $tfa_token) {
                $self->session(logged_in => 1);
                $self->session(password => '');
                $self->session(key => $key);
                return 1;
            } else {
                $self->flash(msg => 'Invalid login', type => 'danger');
                $self->session(logged_in => 0);
                $self->session(target => $self->req->url->to_abs->path);
                $self->redirect_to('/login');
                return 0;
            }
        } else {
            $self->flash(msg => 'Invalid login', type => 'danger');
            $self->session(logged_in => 0);
            $self->session(target => $self->req->url->to_abs->path);
            $self->redirect_to('/login');
            return 0;
        }
    });
}

1;
