package Sesame;
use Mojo::Base 'Mojolicious';
use Sesame::Model;


# This method will run once at server start
sub startup {
    my $self = shift;
  
    my $config = $self->plugin('Config');
    $self->secrets($config->{secret});

    $self->plugin('Sesame::Helpers');
  
    # Router
    my $r = $self->routes;
  
    # Normal route to controller
    $r->get('/')->to('sesame#index')->name('index');
    $r->any('/login')->to('sesame#login');
    $r->any('/register')->to('sesame#register');
    $r->get('/about)')->to('sesame#about');
    my $l = $r->under(sub {
        my $self = shift;
        return $self->auth;
    });
    $l->get('/logout')->to('sesame#logout');
    $l->get('/logins')->to('sesame#logins_list');
    $l->post('/logins')->to('sesame#create');
    $l->get('/logins/new')->to('sesame#form');
    $l->get('/logins/delete/:id')->to('sesame#delete');
    $l->get('/logins/:id')->to('sesame#show');
}

1;
