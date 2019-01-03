#!/usr/bin/env perl

# load perl Default Libs
use strict;
use warnings;
use Cwd qw(getcwd);
use Config::IniFiles;
use FindBin qw( $RealBin );

# load custom lib
use lib "$RealBin/lib";
use CommandParser qw(get_options);
use Patch;
use Utils;
use Extractor;
use GitHandler;

# Dump / log lib
use Data::Dumper;

# start variables
my $current_dir = getcwd();
my $utils = new Utils;
my $extractor = new Extractor;

# parse config.ini file
my %config_ini;
tie %config_ini, 'Config::IniFiles', (  -file => $current_dir."/config/config.ini" );

# parse command line arguments
my $command_line_arguments = CommandParser::get_options(
    {
        skip      => 0,
    }, {
        'server=s'            => 'server name in config.ini',
        'skip=s'              => 'skip steps in script',
        'check_files'         => 'force re-check of previously downloaded files',
        'force|f'             => 'force download even if the allow-url says we are not allowed to',
    }
);

# define config variable
my $config;

# try to set config value
if($command_line_arguments->{'server'}) {
    $config = $config_ini{$command_line_arguments->{'server'}};
} elsif ($config_ini{'app'}{'default_server'}) {
    $config = $config_ini{$config_ini{'app'}{'default_server'}};
} else {
    print "[SCRIPT] I can't find 'default_server' in config and argument 'server' not filled.\n";
    exit;
}

# fail in set config value
if(!$config) {
    print "[SCRIPT] ERROR while try to use config{'server'}, server name is wrong. Check default_server in config.ini or --server arg.\n";
    exit;
}

# start Git Handler
my $git = new GitHandler($config->{'server'});

# start patch
my $patch = new Patch($config);

# checking git dir 
$git->setup_git_dir( $config->{git_root} );

# check if patch is allowed
print "[SCRIPT] Checking patch_allow...\n";

if (!$command_line_arguments->{'force'} && !$patch->patch_allowed() ) {
    print "[SCRIPT] Patching is not currently allowed. You may use --force to force patching.\n";
    exit;
} else {
     print "[SCRIPT] Patching is allowed!\n";
}

# steps to download files
print "[SCRIPT] Downloading and checking patch list file.\n";
$utils->createDir($current_dir.'/'.$config->{'download_dir'});
$utils->createDir($current_dir.'/'.$config->{'download_dir'}.'/extracted_files');
$utils->createDir($current_dir.'/'.$config->{'download_dir'}.'/extracted_files/system');

my $patch_list = $patch->check_patch_list();
    
if(!$patch_list) {
    print "[SCRIPT] Error not possible fetch patch_list!\n";
}

# compare files in repo with local files
if($command_line_arguments->{'check_files'} || $config->{'check_files'}) {
    print "[SCRIPT] Comparing FTP and Local Files.\n";
    $patch->compare_local_and_ftp_files($patch_list);
}

my $recent_patches = [ grep {$_} ( reverse @$patch_list )[ 0 .. 20 ] ];

# download files
print "[SCRIPT] Downloading Files...\n";
$patch->download_ftp_files($recent_patches, $current_dir);

# extract files
print "[SCRIPT] Extracting RGZ Files...\n";
$patch->extract_all_rgz_files($recent_patches, $current_dir);

print "[SCRIPT] Extracting GPF Files...\n";
$patch->extract_all_gpf_files($recent_patches, $current_dir);

# extract infos
print "[SCRIPT] Converting itemInfo.lub...\n";
$patch->convert_iteminfo_lub($current_dir);

# Load old tables and extract recvpackets
print "[SCRIPT] Loading Current Tables Files and Ragexe (also extract packets here)...\n";
$extractor->load_current_tables_files( $current_dir.'/'.$config->{'download_dir'}.'/extracted_files/'.$config->{'executable'}, $config->{'git_connection_dir'}."/recvpackets.txt", $config->{'git_connection_dir'}."/shuffle.txt" );

# write recvpackets
print "[SCRIPT] Writing recvpackets...\n";
$extractor->write_recvpackets( $current_dir.'/'.$config->{'download_dir'}."/extracted_files/recvpackets.txt" );

# write sync
print "[SCRIPT] Writing sync...\n";
$extractor->write_sync( $current_dir.'/'.$config->{'download_dir'}."/extracted_files/sync.txt" );

# update cryptkeys in servers.txt
print "[SCRIPT] Updating CryptKeys...\n";
$extractor->update_cryptkeys( $config->{'git_root'}."/tables/servers.txt", $config->{'servers_block_name'} );

# generate and write shuffle file
print "[SCRIPT] Writing Shuffle...\n";
$extractor->generate_shuffle();
$extractor->write_shuffle( $current_dir.'/'.$config->{'download_dir'}.'/extracted_files/shuffle.txt' );

# prepare to commit
print "[SCRIPT]Setuping Openkore Git DIR to commit...\n";
$git->setup_git_dir_to_commit( $config->{git_root}, $config->{branch} );

# move files to openkore git dir
print "[SCRIPT] Moving files to Openkore Git DIR...\n";
$patch->move_files_tables_to_git_directory($current_dir);
$patch->move_files_connection_to_git_directory($current_dir);

# make pull request
print "[SCRIPT] Commiting and making pull-request...\n";
$git->commit( $config->{branch}, $config->{'server'} );

exit;