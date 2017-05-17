package Sesame::Model::User;
use Mandel::Document;
use Types::Standard qw( Str Int ArrayRef HashRef Num );

field username => ( isa => Str );
field password => ( isa => Str );
field tfa_secret => (isa => Str );
has_many logins => 'Sesame::Model::Login';

1;
