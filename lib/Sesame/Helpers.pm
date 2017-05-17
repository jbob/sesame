package Sesame::Helpers;

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::IOLoop;

use Authen::OATH;
use Convert::Base32;

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

    $app->helper(auth => sub {
        my $con = shift;
        return 1 if $con->session
                  and $con->session('logged_in')
                  and $con->session('logged_in') == 1;
        if (not $con->session('username')) {
            $con->session(logged_in => 0);
            $con->session(target => $con->req->url->to_abs->path);
            $con->redirect_to('/login');
            return 0;
        }

        my $username = $con->session('username');
        my $password = $con->session('password');
        #my $result = 0;
        #$app->delay(sub {
        #    $app->users->search({ username => $username, password => $password })->single(sub {
        #        my ($users, $err, $user) = @_;
        #        $app->reply->exception($err) if $err;
        #        if ($user) {
        #            #my $tfa_secret = decode_base32 $doc->tfa_secret;
        #            my $tfa_secret = decode_base32 $user->tfa_secret;
        #            my $correct_token = make_token_6(Authen::OATH->new->totp($tfa_secret));
        #            my $tfa_token = $con->session('tfa_token');
        #            if ($correct_token eq $tfa_token) {
        #                $con->session('logged_in' => 1);
        #                $con->session(password => '');
        #                #return 1;
        #                sleep 3;
        #                warn "Success!";
        #                $result = 1;
        #            } else {
        #                $con->flash(msg => 'Invalid login', type => 'danger');
        #                $con->session(logged_in => 0);
        #                $con->session(target => $con->req->url->to_abs->path);
        #                $con->redirect_to('/login');
        #                #return 0;
        #                $result = 0;
        #            }
        #        } else {
        #            $con->flash(msg => 'Invalid login', type => 'danger');
        #            $con->session(logged_in => 0);
        #            $con->session(target => $con->req->url->to_abs->path);
        #            $con->redirect_to('/login');
        #            #return 0;
        #            $result = 0;
        #        }
        #    });
        #})->wait;
        #return $result;
        my $user = $app->users->search({ username => $con->session('username'), password => $con->session('password')})->single;
        warn "ZZZ".$user;
        if ($user) {
            my $tfa_secret = decode_base32 $user->tfa_secret;
            my $correct_token = make_token_6(Authen::OATH->new->totp($tfa_secret));
            my $tfa_token = $con->session('tfa_token');
            if ($correct_token eq $tfa_token) {
                $con->session('logged_in' => 1);
                $con->session(password => '');
                return 1;
            } else {
                $con->flash(msg => 'Invalid login', type => 'danger');
                $con->session(logged_in => 0);
                $con->session(target => $con->req->url->to_abs->path);
                $con->redirect_to('/login');
                return 0;
            }
        } else {
            $con->flash(msg => 'Invalid login', type => 'danger');
            $con->session(logged_in => 0);
            $con->session(target => $con->req->url->to_abs->path);
            $con->redirect_to('/login');
            return 0;
        }
    });
}

1;
