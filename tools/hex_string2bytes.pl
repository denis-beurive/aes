#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

my $data = <<'EOS';
603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4:f69f2445df4f9b17ad2b417be66c3710:23304b7a39f9f3ff067d8d8f9e24ecc7
EOS

sub split_hex_key {
    my ($s) = @_;
    my @tokens = ();
    for (my $i=0; $i<length($s)/2; $i++) {
        push(@tokens, substr($s, 2*$i, 2));
    }
    return(@tokens);
}

sub split_hex_state {
    my ($s) = @_;
    my @tokens = ();
    my @by_columns = ();

    for (my $i=0; $i<length($s)/2; $i++) {
        push(@tokens, substr($s, 2*$i, 2));
    }
    # for (my $column=0; $column<4; $column++) {
    #     for (my $line=0; $line<4; $line++) {
    #         push(@by_columns, $tokens[4*$line + $column]);
    #     }
    # }

    return(@tokens);
    # return(@by_columns);
}


my @tests = split(/\n/, $data);
my $count = 0;
foreach my $test (@tests) {
    my ($key, $plain, $cypher) = split(/:/, $test);

    printf("const uint8_t key%d[32]    = { %s };\n", $count, join(', ', map { sprintf('0x%s', $_) } split_hex_key($key)));
    printf("plain: %s\n", $plain);
    printf("const uint8_t plain%d[16]  = { %s };\n", $count, join(', ', map { sprintf('0x%s', $_) } split_hex_state($plain)));
    printf("cypher: %s\n", $cypher);
    printf("const uint8_t cypher%d[16] = { %s };\n", $count, join(', ', map { sprintf('0x%s', $_) } split_hex_state($cypher)));

    $count++;
}






