#!/usr/bin/env perl
package Extractor;

use strict;
use warnings;

use Disassemble::X86;
use Time::Piece;

my $cryptkeys;
my $recvpackets;
my $old_recvpackets;
my $old_shuffle;
my $ragexe;
my $shuffle;
my $opt;
my $shuffle_style = "new";

sub new {
    my $class = shift;
    $opt->{'verbose'} = 0;
    return bless {}, $class;
}

sub load_current_tables_files {
    my ($self, $old_ragexe_path, $old_recvpackets_path, $old_shuffle_path ) = @_;
    $ragexe = $old_ragexe_path;
    $cryptkeys       = extract_cryptkeys( $ragexe );
    $recvpackets     = extract_recvpackets( $ragexe );
    $old_recvpackets = load_recvpackets( $old_recvpackets_path );
    $old_shuffle     = load_shuffle( $old_shuffle_path );
}

# Load the old recvpackets.txt.
# If a shuffle.txt was given, unshuffle the old recvpackets.txt with it.
# Generate a new shuffle.txt from the old and new recvpackets.txt.
sub generate_shuffle {
    my ( $self ) = @_;
	my $new_recvpackets = $recvpackets;
    $shuffle = [];
    if ( $shuffle_style eq "old" ) {
        my $openkore_shuffle = [qw(0089 0113 0437 0360 0361 0362 0363 0364 0365 0366 0367 0368 0369 087B 0838 0835 0819 0817 0815 0811 0802 093E 07E4 0436 02C4 087E 0202 022D 023B)];
        foreach ( 0 .. $#$openkore_shuffle ) {
            my $old = $openkore_shuffle->[$_];
            my $new = $new_recvpackets->[$_]->{id};
            push @$shuffle, { from => $old, to => $new };
        }
    } else {
        my $new_recvpackets = $recvpackets;
        # Unshuffle the old recvpackets.
        if ( $old_shuffle && @$old_shuffle ) {
            my $reverse_map = { map { $_->{to} => $_->{from} } @$old_shuffle };
            my $unshuffled = [];
            foreach ( @$old_recvpackets ) {
                push @$unshuffled, { %$_, id => $reverse_map->{ $_->{id} } || $_->{id} };
            }
            $old_recvpackets = $unshuffled;
        }

        # HACK: Add new packets.
        my %new_packets = map { $_ => $_ } qw();
        delete $new_packets{ $_->{id} } foreach @$old_recvpackets;
        for ( my $i = 0; $i < $#$new_recvpackets; $i++ ) {
            my $id = $new_recvpackets->[$i]->{id};
            next if !$new_packets{ $id };
            next if (!grep { $new_recvpackets->[$_]->{id} eq $old_recvpackets->[$i]->{id} } values %{$new_recvpackets});
            splice @$old_recvpackets, $i, 0, { id => $id };
        }
        if (@$old_recvpackets != @$new_recvpackets) {
            die sprintf "ERROR: Size of recvpackets changed [%d != %d], shuffle will be wrong. Indicate new packets.\n", scalar @$old_recvpackets, scalar @$new_recvpackets;
        }

        # Generate the shuffle!
        
        foreach ( 0 .. $#$new_recvpackets ) {
            my $old = $old_recvpackets->[$_]->{id};
            my $new = $new_recvpackets->[$_]->{id};
            next if $old eq $new;
            push @$shuffle, { from => $old, to => $new };
        }
    }
}

sub write_shuffle {
    my ( $self, $file ) = @_;

    open FP, '>', $file;
    print FP sprintf "# Script by alisonrag\n# Generated: %sZ\n", gmtime()->datetime;
    foreach ( @$shuffle ) {
        print FP sprintf "%s %s\n", $_->{from}, $_->{to};
    }
    close FP;
}

sub load_recvpackets {
    my ( $file ) = @_;

    return [] if !$file || !-r $file;

    open FP, '<', $file;
    my $recvpackets = [];
    while ( <FP> ) {
        next if !/^([0-9A-F]{4}) (-?\d+) (-?\d+) (-?\d+)/os;
        push @$recvpackets, { id => $1, length => $2, min_length => $3, repeat => $4 };
    }
    close FP;

    $recvpackets;
}

sub load_shuffle {
    my ( $file ) = @_;

    return [] if !$file || !-r $file;

    open FP, '<', $file;
    my $shuffle = [];
    while ( <FP> ) {
        next if !/^([0-9A-F]{4}) ([0-9A-F]{4})/os;
        push @$shuffle, { from => $1, to => $2 };
    }
    close FP;

    $shuffle;
}

sub update_cryptkeys {
    my ( $self, $file, $block ) = @_;

    return if !-f $file;

    open FP, '<', $file;
    my @lines = <FP>;
    close FP;

    # Find the first and last line of the given block.
    my $line1 = -1;
    my $line2 = -1;
    my $linec = -1;
    foreach ( 0 .. $#lines ) {
        my $line = $lines[$_];
        $line1 = $_ if $line =~ /^\[\Q$block\E\]/;
        $line2 = $_;
        $linec = $_ if $line1 > -1 && $line =~ /^\s*sendCryptKeys /;
        last if $line1 > -1 && $line1 != $_ && substr( $line, 0, 1 ) eq '[';
    }
    if ( $line1 != -1 && $linec == -1 ) {
        $linec = $line2;
        $linec-- while $lines[ $linec - 1 ] =~ /^\s*(#|$)/os;
        splice @lines, $linec, 0, '';
    }
    if ( $linec ) {
        $lines[$linec] = sprintf "sendCryptKeys 0x%08s, 0x%08s, 0x%08s\n", uc $cryptkeys->[0], uc $cryptkeys->[1], uc $cryptkeys->[2];
    }

    if ( $linec > -1 ) {
        open FP, '>', $file;
        print FP $_ foreach @lines;
        close FP;
    }
}

sub write_recvpackets {
    my ( $self, $file ) = @_;

    open FP, '>', $file;
    print FP sprintf "# Script by alisonrag\n# Generated: %sZ\n", gmtime()->datetime;
    foreach ( @$recvpackets ) {
        print FP sprintf "%s %s %s %s\n", @$_{qw( id length min_length repeat )};
    }
    close FP;
}

# Generate sync.txt.
# Find a block of 168 consecutive packets with a "2 2 0" signature. Ideally we'd look for packet IDs (085A-0883, 0917-0940) => (0884-08AD, 0941-096A), but packet shuffling makes that hard.
sub write_sync {
    my ( $self, $file ) = @_;

    open FP, '>', $file;
    print FP sprintf "# Script by alisonrag\n# Generated: %sZ\n", gmtime()->datetime;
    for ( my $i = 0 ; $i < @$recvpackets ; $i++ ) {
        next if $recvpackets->[$i]->{length} != 2;
        my $j = $i;
        $j++ while $j < @$recvpackets && $recvpackets->[$j]->{length} == 2;
        my $len = $j - $i;
        next if $len < 168;
        if ( $len > 168 ) {
            print FP sprintf "# WARNING: There should be exactly 168 sync packets, but %d packets were found. This may be incorrect.\n", $len;
        }
        foreach ( 0 .. 83 ) {
            print FP sprintf "%s %s\n", $recvpackets->[ $i + $_ ]->{id}, $recvpackets->[ $i + 84 + $_ ]->{id};
        }
    }
    close FP;
}

# Search for e8 3f 70 00 00.
# Load up 100k of code.
# Disassemble.
# Emulate.
sub extract_recvpackets {
    my ( $file ) = @_;

    # Search for the recvpackets definition function.
    my $recvpackets_code = get_recvpackets_code( $file );
    if ( !$recvpackets_code ) {
        print "Failed to extract recvpackets function.\n";
        return;
    }

    # Disassemble the function.
    my $disasm = Disassemble::X86->new( text => $recvpackets_code );

    my $recvpackets = [];

    my $stack = [];
    while ( my $op = $disasm->disasm ) {
        printf "%04x  %-14s  %s\n", $disasm->op_start, unpack( 'H*', substr $recvpackets_code, $disasm->op_start, $disasm->op_len ), $op if $opt->{verbose};

        # There are two ways to add to the stack: "mov dword[ss:ebp+$offset],$val" and "push dword(0x1)".
        if ( $op =~ /^mov dword\[ss:ebp\+0x([0-9a-f]+)\],0x([0-9a-f]+)/o ) {
            use integer;
            my ( $offset, $val ) = ( 0xffffffff - hex( $1 ) + 1, hex( $2 ) );
            $val = $val - 0xffffffff - 1 if $val > 0xffff;

            # $stack->[ $offset / 4 - 1 ] = $val;
            push @$stack, $val;
        }

        if ( $op =~ /^push dword\(0x([0-9a-f]+)\)/o ) {
            use integer;
            my $val = hex $1;
            $val = $val - 0xffffffff - 1 if $val > 0xffff;
            unshift @$stack, $val;
        }

        if ( $op =~ /^call 0x([0-9a-f]+)/o && @$stack ) {
            last if @$stack != 1 && @$stack != 4;
            if ( @$stack == 4 ) {
                push @$recvpackets, { id => sprintf( '%04X', $stack->[0] ), length => $stack->[1], min_length => $stack->[2], repeat => $stack->[3] };
            }
            @$stack = ();
        }

        if ( $op =~ /^ret$/o ) {
            @$stack = ();
        }
    }

    $recvpackets;
}

sub extract_cryptkeys {
    my ( $file ) = @_;

    # Search for the cryptKeys definition function.
    my $cryptkeys_codes = get_cryptkeys_code( $file );

    foreach my $cryptkeys_code ( @$cryptkeys_codes ) {

        # Disassemble the function.
        my $disasm = Disassemble::X86->new( text => $cryptkeys_code );

        my $stack = [];
        while ( my $op = $disasm->disasm ) {
            printf "%04x  %-14s  %s\n", $disasm->op_start, unpack( 'H*', substr $cryptkeys_code, $disasm->op_start, $disasm->op_len ), $op if $opt->{verbose};;
            if ( $op =~ /^mov dword\[ecx\+0x([0-9a-f]+)\],0x([0-9a-f]+)/o ) {
                push @$stack, $2;
            }

            if ( $op =~ /^call /o && @$stack ) {
                @$stack = ();
            }

            if ( $op =~ /^ret /o ) {
                return [ @$stack[ 0, 2, 1 ] ] if @$stack == 3;
                @$stack = ();
            }
        }
    }

    [];
}

sub get_recvpackets_code {
    my ( $file ) = @_;

    # Stopped working 2017-09-20.
    # find_code( $file, "\xe8\x3f\x70\x00\x00", 100 * 1024 )->[0];
    # find_code( $file, "\xe8\x0f\x71\x00\x00", 100 * 1024 )->[0];
    # find_code( $file, "\xe8\x1f\x71\x00\x00", 100 * 1024 )->[0];

    # Search for a "mov DWORD PTR [ebp-0x??],0x187" instruction.
    # NOTE: This is roughly at offset 0x4fa440 in the file.
    my ( $part1, $part2 ) = ( "\xc7\x45", "\x87\x01\x00\x00" );

    my $locs = find_code_locations( $ragexe, $part2, 3, 0 );
    $locs = [ grep { substr( $_->{bytes}, 0, 2 ) eq $part1 } @$locs ];
    if ( @$locs != 1 ) {
        print "Unable to determine start of recvpackets definition function. @{[scalar @$locs]} possible locations found.\n";
        exit 1;
    }

    # TODO: If we ever have to search for a packet which isn't the first
    # one, we'll need to back up a bit.  Maybe search for 0xcc ("int3", used
    # as padding between functions) or 0xc3 ("ret")?

    # Get 100k of data starting from the location we found.
    open FP, '<', $file;
    seek FP, $locs->[0]->{offset} - 3, 0;
    my $buf;
    read FP, $buf, 100 * 1024;
    close FP;

    $buf;
}

sub get_cryptkeys_code {
    my ( $file ) = @_;
    find_code( $file, "\x83\xf8\x01\x75\x1b", 40, 1 );
}

sub find_code_locations {
    my ( $file, $pat, $bytes_before, $bytes_after ) = @_;
    
    my $result = [];

    my $len = length $pat;

    open FP, '<', $file;
    my $buf = '';
    my $off = 0;
    while ( read FP, $buf, 8192, length $buf ) {
        my $buflen = length $buf;
        for ( my $i = 0 ; $i < $buflen - $len - $bytes_after ; $i++ ) {
            next if $pat ne substr $buf, $i, $len;
            push @$result, { offset => $off + $i, bytes => substr $buf, $i - $bytes_before, $bytes_before + $len + $bytes_after };
        }
        $buf = substr $buf, $buflen - ( $len + $bytes_before );
        $off += $buflen - ( $len + $bytes_before );
    }
    close FP;

    $result;
}

# Search for a pattern and load $bytes bytes worth of code after it. Return.
sub find_code {
    my ( $file, $pat, $bytes, $all ) = @_;

    my $result = [];

    my $len = length $pat;

    open FP, '<', $file;
    my $buf = '';
    while ( read FP, $buf, 8192, length $buf ) {
        my $buflen = length $buf;
        for ( my $i = 0 ; $i < $buflen - $len ; $i++ ) {
            next if $pat ne substr $buf, $i, $len;
            my $tmp = substr $buf, $i, $bytes;
            read FP, $tmp, $bytes - length $tmp, length $tmp if $bytes > length $tmp;
            push @$result, $tmp;
            last if !$all;
        }
        $buf = substr $buf, -$len + 1;
    }
    close FP;

    $result;
}

1;