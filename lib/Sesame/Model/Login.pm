package Sesame::Model::Login;
use Mandel::Document;
use Types::Standard qw( Str Int ArrayRef HashRef Num );

field page       => ( isa => Str );
field login      => ( isa => Str );
field password   => ( isa => Str );
field comment    => ( isa => Str );
belongs_to user  => 'Sesame::Model::User';

1;
