#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

my $tests = [
    [[0xdb, 0x13, 0x53, 0x45], [0x8e, 0x4d, 0xa1, 0xbc]],
    [[0xf2, 0x0a, 0x22, 0x5c], [0x9f, 0xdc, 0x58, 0x9d]],
    [[0x01, 0x01, 0x01, 0x01], [0x01, 0x01, 0x01, 0x01]],
    [[0xc6, 0xc6, 0xc6, 0xc6], [0xc6, 0xc6, 0xc6, 0xc6]],
    [[0xd4, 0xd4, 0xd4, 0xd5], [0xd5, 0xd5, 0xd7, 0xd6]],
    [[0x2d, 0x26, 0x31, 0x4c], [0x4d, 0x7e, 0xbd, 0xf8]]
];

for (my $delta=0; $delta<3; $delta++) {
    my @input = ();
    my @output = ();

    for(my $column=0; $column<4; $column++) {
        for (my $line=$delta; $line<4+$delta; $line++) {
            push(@input, $tests->[$line][0][$column]);
            push(@output, $tests->[$line][1][$column]);
        }
    }

    printf("const uint8_t input%d[16] = { %s, \n", $delta, join(', ', map{ sprintf('0x%02X', $_) } @input[0..3]));
    printf("                              %s, \n", join(', ', map{ sprintf('0x%02X', $_) } @input[4..7]));
    printf("                              %s, \n", join(', ', map{ sprintf('0x%02X', $_) } @input[8..11]));
    printf("                              %s };\n", join(', ', map{ sprintf('0x%02X', $_) } @input[12..15]));


    printf("const uint8_t output%d[16] = { %s, \n", $delta, join(', ', map{ sprintf('0x%02X', $_) } @output[0..3]));
    printf("                               %s, \n", join(', ', map{ sprintf('0x%02X', $_) } @output[4..7]));
    printf("                               %s, \n", join(', ', map{ sprintf('0x%02X', $_) } @output[8..11]));
    printf("                               %s };\n", join(', ', map{ sprintf('0x%02X', $_) } @output[12..15]));

}

