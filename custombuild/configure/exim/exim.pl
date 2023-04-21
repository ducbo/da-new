#!/usr/bin/perl

#VERSION=32

sub get_domain_owner
{
	my ($domain) = @_;
	my $username="";
	open(DOMAINOWNERS,"/etc/virtual/domainowners");
	while (<DOMAINOWNERS>)
	{
		$_ =~ s/\n//;
		my ($dmn,$usr) = split(/: /, $_);
		if ($dmn eq $domain)
		{
			close(DOMAINOWNERS);
			return $usr;
		}
	}
	close(DOMAINOWNERS);

	return -1;
}

sub safe_name
{
	my ($name) =  @_;

	if ($name =~ /\//)
	{
		return 0;
	}

	if ($name =~ /\\/)
	{
		return 0;
	}
	
	if ($name =~ /\|/)
	{
		return 0;
	}

	if ($name =~ /\.\./)
	{
		return 0;
	}

	return 1;
}

# hit_limit_user
# checks to see if a username has hit the send limit.
# returns:
#	-1 for "there is no limit"
#	0  for "still under the limit"
#	1  for "at the limit"
#	2  for "over the limit"

sub hit_limit_user
{
	my($username) = @_;

	my $count = 0;
	my $email_limit = 0;

	if (!safe_name($username))
	{
		return 2;
	}
	
	if (open (LIMIT, "/etc/virtual/limit_$username"))
	{
		$email_limit = int(<LIMIT>);
		close(LIMIT);
	}
	else
	{
		open (LIMIT, "/etc/virtual/limit");
		$email_limit = int(<LIMIT>);
		close(LIMIT);
	}

	if ($email_limit > 0)
	{
		#check this users limit
		$count = (stat("/etc/virtual/usage/$username"))[7] + 1;

		#this is their last email.
		if ($count == $email_limit)
		{
			return 1;
		}

		if ($count > $email_limit)
		{
			return 2;
		}

		return 0;
	}

	return -1;
}

# hit_limit_email
# same idea as hit_limit_user, except we check the limits (if any) for per-email accounts.

sub hit_limit_email
{
	my($user,$domain) = @_;

	if (!safe_name($user) || !safe_name($domain))
	{
		return 2;
	}
	
	my $user_email_limit = 0;
	if (open (LIMIT, "/etc/virtual/$domain/limit/$user"))
	{
		$user_email_limit = int(<LIMIT>);
		close(LIMIT);
	}
	else
	{
		if (open (LIMIT, "/etc/virtual/user_limit"))
		{
			$user_email_limit = int(<LIMIT>);
			close(LIMIT);
		}
	}

	if ($user_email_limit > 0)
	{
		my $count = 0;
		$count = (stat("/etc/virtual/$domain/usage/$user"))[7] + 1;
		if ($count == $user_email_limit)
		{
			return 1;
		}
		if ($count > $user_email_limit)
		{
			return 2;
		}
		return 0;
	}

	return -1;
}

#function to die if the User account or email is over limit
sub die_if_over_limit
{
	my($check_limits,$email_user,$domain) = @_;

	if ($check_limits == 0)
	{
		return;
	}

	my $domain_owner = get_domain_owner($domain);

	if ($domain_owner == -1)
	{
		return;
	}

	my $limit_check = hit_limit_user($domain_owner);
	if ($limit_check > 1)
	{
		die("The email send limit for $domain_owner has been reached\n");
	}

	$limit_check = hit_limit_email($email_user, $domain);
	if ($limit_check > 1)
	{
		die("The email send limit for $email_user\@${domain} has been reached\n");
	}
}


#smtpauth
#called by exim to verify if an smtp user is allowed to
#send email through the server
#possible success:
# user is in /etc/virtual/domain.com/passwd and password matches
# user is in /etc/passwd and password matches in /etc/shadow

sub smtpauth
{
	$username	= Exim::expand_string('$1');
	$password	= Exim::expand_string('$2');
	$extra		= Exim::expand_string('$3');
	$domain		= "";
	$unixuser	= 1;

	my ( $check_limits ) = @_;
	if (defined $check_limits && $check_limits eq "0")
	{
		$check_limits = 0;
	}
	else
	{
		$check_limits = 1;
	}

	#check for netscape that offsets the login/pass by one
	if (length($extra) > 0 )
	{
		if ($username eq "" || $username eq $password)
		{
			$username = $password;
			$password = $extra;
		}
	}

	$username =~ s/^\s+|\s+$//g;
	$username =~ s/([[:upper:]])/\l$1/g;

	if (!safe_name($username))
	{
		Exim::log_write("SMTPAuth: Invalid username: $username");
		return "no";
	}
	
	if ($username =~ /\@/)
	{
		$unixuser = 0;
		($username,$domain) = split(/\@/, $username);
		if ($domain eq "") { return "no"; }
	}

	if ($unixuser == 1)
	{
			#the username passed doesn't have a domain, so its a system account
			$homepath = (getpwnam($username))[7];
			if ($homepath eq "") { return 0; }
			if (open(PASSFILE, "< $homepath/.shadow")) {
					$crypted_pass = <PASSFILE>;
					close PASSFILE;

					if ($crypted_pass eq crypt($password, $crypted_pass))
					{
							if ($check_limits == 1)
							{
									my $limit_check = hit_limit_user($username);
									if ($limit_check > 1)
									{
											die("The email send limit for $username has been reached\n");
									}
							}

							return "yes";
					}
			}

			#jailed shell auth
			if (open(USERVARIABLES,"/etc/exim.jail/$username.conf"))
			{
					while ($line = <USERVARIABLES>)
					{
							if ($line =~ m/^password /)
							{
									my $jail_password = (split / /, $line)[1];
									$jail_password =~ s/\n//;
									if ($jail_password eq $password) {
											if ($check_limits == 1)
											{
													my $limit_check = hit_limit_user($username);
													if ($limit_check > 1)
													{
															die("The email send limit for $username has been reached\n");
													}
											}
											close(USERVARIABLES);
											return "yes";
									}
							}
					}
					close(USERVARIABLES);
			}

	}
	else
	{
		#the username contain a domain, which is now in $domain.
		#this is a pure virtual pop account.

		open(PASSFILE, "< /etc/virtual/$domain/passwd") || return "no";
		while (<PASSFILE>)
		{
			($test_user,$test_pass) = split(/:/,$_);
			$test_pass =~ s/\n//g; #snip out the newline at the end
			if ($test_user eq $username)
			{
				close PASSFILE;
				if ($test_pass eq crypt($password, $test_pass))
				{
					die_if_over_limit($check_limits, $username, $domain);
					return "yes";
				}

				#right user in passwd
				#wrong password in passwd

				#unless, they have a passwd_alt file, lets try that
				open(PASSFILE_ALT, "< /etc/virtual/$domain/passwd_alt") || return "no";
				while (<PASSFILE_ALT>)
				{
					($test_user,$test_pass) = split(/:/,$_);
					$test_pass =~ s/\n//g; #snip out the newline at the end
					if ($test_user eq $username)
					{
						close PASSFILE_ALT;
						if ($test_pass eq crypt($password, $test_pass))
						{
							die_if_over_limit($check_limits, $username, $domain);
							return "yes";
						}
						return "no";	#wrong password vs passwd_alt
					}
				}
				close PASSFILE_ALT;
				return "no";	#not found in passwd_alt
			}
		}
		close PASSFILE;
		return "no";	#not found in passwd
	}

	return "no";
}

sub auth_hit_limit_acl
{
	my $authenticated_id	= Exim::expand_string('$authenticated_id');

	$username	= $authenticated_id;
	$domain		= "";
	$unixuser	= 1;

	if (!safe_name($username))
	{
		Exim::log_write("auth_hit_limit_acl: Invalid username: $username");
		return "yes";
	}

	if ($username =~ /\@/)
	{
		$unixuser = 0;
		($username,$domain) = split(/\@/, $username);
		if ($domain eq "") { return "no"; }
	}
	
	if ($unixuser == 1)
	{
		my $limit_check = hit_limit_user($username);
		if ($limit_check > 1)
		{
			return "yes";
		}
	}
	else
	{
		my $domain_owner = get_domain_owner($domain);
		if ($domain_owner != -1)
		{
			my $limit_check = hit_limit_user($domain_owner);
			if ($limit_check > 1)
			{
				return "yes";
			}

			$limit_check = hit_limit_email($username, $domain);
			if ($limit_check > 1)
			{
				return "yes";
			}
		}
	}

	return "no";
}

sub find_uid_apache
{
	my ($work_path) = @_;
	my @pw;
	
	# $pwd will probably look like '/home/username/domains/domain.com/public_html'
	# it may or may not use /home though. others are /usr/home, but it's ultimately
	# specified in the /etc/passwd file.  We *could* parse through it, but for efficiency
	# reasons, we'll only check /home and /usr/home ..   if they change it, they can
	# manually adjust if needed.

	@dirs = split(/\//, $work_path);
	foreach $dir (@dirs)
	{
		# check the dir name for a valid user
		# get the home dir for that user
		# compare it with the first part of the work_path

		if ( (@pw = getpwnam($dir))  )
		{
			if ($work_path =~/^$pw[7]/)
			{
				return $pw[2];
			}
		}
	}
	return -1;
}

sub find_uid_auth_id
{
	# this will be passwed either
	# 'username' or 'user@domain.com'

	my ($auth_id) = @_;
	my $unixuser = 1;
	my $domain = "";
	my $user = "";
	my $username = $auth_id;
	my @pw;

	if (!safe_name($username))
	{
		Exim::log_write("find_uid_auth_id: Invalid username: $username");
		return "-1";
	}
	
	if ($auth_id =~ /\@/)
	{
		$unixuser = 0;
		($user,$domain) = split(/\@/, $auth_id);
		if ($domain eq "") { return "-1"; }
        }

	if (!$unixuser)
	{
		# we need to take $domain and get the user from /etc/virtual/domainowners
		# once we find it, set $username
		my $u = get_domain_owner($domain);;
		if ($u != -1)
		{
			$username = $u;
		}
	}

	#log_str("username found from $auth_id: $username:\n");

	if ( (@pw = getpwnam($username))  )
	{
		return $pw[2];
	}

	return -1;
}

sub find_uid_sender
{
	my $sender_address = Exim::expand_string('$sender_address');

	my ($user,$domain) = split(/\@/, $sender_address);

	my $primary_hostname = Exim::expand_string('$primary_hostname');
	if ( $domain eq $primary_hostname )
	{
		@pw = getpwnam($user);
		return $pw[2];
	}

	my $username = get_domain_owner($domain);

	if ( (@pw = getpwnam($username))  )
	{
		return $pw[2];
	}

	return -1;
}

sub get_username
{
	my ($uid) = @_;
	if ($uid == -1) { return "unknown" };
	my $name = getpwuid($uid);
	return $name;
}

sub find_script_path
{
	my $work_path = $ENV{'PWD'};
	return $work_path;
}

sub get_env
{
	my ($envvar) = @_;
	if ($envvar eq "" ) { return ""; };
	return $ENV{$envvar};
}

sub find_uid
{
        my $uid = Exim::expand_string('$originator_uid');
	my $username = getpwuid($uid);
        my $auth_id = Exim::expand_string('$authenticated_id');
        my $work_path = $ENV{'PWD'};

	if ($username eq "apache" || $username eq "nobody" || $username eq "webapps")
	{
		$apache_uid = find_uid_apache($work_path);
		if ($apache_uid != -1) { return $apache_uid; }
	}

	if ($username ne "" && -d "/usr/local/directadmin/data/users/$username" )
	{
		return $uid;
	}
	
	$auth_uid = find_uid_auth_id($auth_id);
	if ($auth_uid != -1) { return $auth_uid; }

	# we don't want to rely on this, but it's all thats left.
	return find_uid_sender;
}

sub uid_exempt
{
        my ($uid) = @_;
        if ($uid == 0) { return 1; }

        my $name = getpwuid($uid);
        if ($name eq "root") { return 1; }
        if ($name eq "diradmin") { return 1; }

        return 0;
}


#check_limits
#used to enforce limits for the number of emails sent
#by a user.  It also logs the bandwidth of the data
#for received mail.

sub check_limits
{
	#find the curent user
	$uid = find_uid();

	#log_str("Found uid: $uid\n");

	if (uid_exempt($uid)) { return "yes"; }

	my $name="";

	#check this users limit
	$name = getpwuid($uid);

	if (!defined($name))
	{
		#possibly the sender-verify
		$name = "unknown";
		#return "yes";
	}

	my $count = 0;
	my $email_limit = 0;
	if (open (LIMIT, "/etc/virtual/limit_$name"))
	{
		$email_limit = int(<LIMIT>);
		close(LIMIT);
	}
	else
	{
		open (LIMIT, "/etc/virtual/limit");
		$email_limit = int(<LIMIT>);
		close(LIMIT);
	}

	my $sender_address 	= Exim::expand_string('$sender_address');
	my $authenticated_id	= Exim::expand_string('$authenticated_id');
	my $sender_host_address	= Exim::expand_string('$sender_host_address');
	my $mid 		= Exim::expand_string('$message_id');
	my $message_size	= Exim::expand_string('$message_size');
	my $local_part		= Exim::expand_string('$local_part');
	my $domain		= Exim::expand_string('$domain');
	my $timestamp		= time();
	my $is_retry = 0;

	if ($mid eq "")
	{
		return "yes";
	}

	if ($email_limit > 0)
	{
		#check this users limit
		$count = (stat("/etc/virtual/usage/$name"))[7] + 1;

		if ($count > $email_limit)
		{
			die("You ($name) have reached your daily email limit of $email_limit emails\n");
		}

		if ($mid ne "")
		{
			if (! -d "/etc/virtual/usage/${name}_ids")
			{
				mkdir("/etc/virtual/usage/${name}_ids", 0770);
			}

			my $mid_char = substr($mid, 0, 1);

			if (! -d "/etc/virtual/usage/${name}_ids/$mid_char")
			{
				mkdir("/etc/virtual/usage/${name}_ids/$mid_char", 0770);
			}
			
			if (! -d "/etc/virtual/usage/${name}_ids/$mid_char/$mid")
			{
				mkdir("/etc/virtual/usage/${name}_ids/$mid_char/$mid", 0770);
			}

			my $dest_str = get_b64_string("$local_part-$domain");
			my $id_file = "/etc/virtual/usage/${name}_ids/$mid_char/$mid/$dest_str";

			if (-f $id_file)
			{
				$is_retry = 1;
			}
			else
			{
				open(IDF, ">>$id_file");
				print IDF "log_time=$timestamp\n";
				close(IDF);
				chmod (0660, $id_file);
			}
		}

		#this is their last email.
		if (($count == $email_limit) && ($is_retry != 1))
		{
			#taddle on the dataskq
			#note that the sender_address here is only the person who sent the last email
			#it doesnt meant that they have sent all the spam
			#this action=limit will trigger a check on usage/user.bytes, and DA will try and figure it out.
			open(TQ, ">>/etc/virtual/mail_task.queue");
			print TQ "action=limit&username=$name&count=$count&limit=$email_limit&email=$sender_address&authenticated_id=$authenticated_id&sender_host_address=$sender_host_address&log_time=$timestamp\n";
			close(TQ);
			chmod (0660, "/etc/virtual/mail_task.queue");
		}

		if ($is_retry != 1)
		{
			open(USAGE, ">>/etc/virtual/usage/$name");
			print USAGE "1";
			close(USAGE);
			chmod (0660, "/etc/virtual/usage/$name");
		}
	}

	if ( ($authenticated_id ne "") && ($is_retry != 1) )
	{
		my $user="";
		my $domain="";
		($user, $domain) = (split(/@/, $authenticated_id));

		if (!safe_name($authenticated_id))
		{
			Exim::log_write("check_limits: Invalid username: $authenticated_id");
			return "no";
		}

		if ($domain ne "")
		{
			my $user_email_limit = 0;
			if (open (LIMIT, "/etc/virtual/$domain/limit/$user"))
			{
				$user_email_limit = int(<LIMIT>);
				close(LIMIT);
			}
			else
			{
				if (open (LIMIT, "/etc/virtual/user_limit"))
				{
					$user_email_limit = int(<LIMIT>);
					close(LIMIT);
				}
			}

			if ($user_email_limit > 0)
			{
				$count = 0;
				$count = (stat("/etc/virtual/$domain/usage/$user"))[7] + 1;

				if ($count == $user_email_limit)
				{
					open(TQ, ">>/etc/virtual/mail_task.queue");
					print TQ "action=userlimit&username=$name&count=$count&limit=$user_email_limit&email=$sender_address&authenticated_id=$authenticated_id&sender_host_address=$sender_host_address&log_time=$timestamp\n";
					close(TQ);
					chmod (0660, "/etc/virtual/mail_task.queue");
				}

				if ($count > $user_email_limit)
				{
					die("Your E-Mail ($authenticated_id) has reached it's daily email limit of $user_email_limit emails\n");
				}

				if (! -d "/etc/virtual/$domain/usage")
				{
					mkdir("/etc/virtual/$domain/usage", 0770);
				}

				if (-d "/etc/virtual/$domain/usage")
				{
					open(USAGE, ">>/etc/virtual/$domain/usage/$user");
					print USAGE "1";
					close(USAGE);
					chmod (0660, "/etc/virtual/$domain/usage/$user");
				}
			}
		}
	}

	log_bandwidth($uid,"type=email&email=$sender_address&method=outgoing&id=$mid&authenticated_id=$authenticated_id&sender_host_address=$sender_host_address&log_time=$timestamp&message_size=$message_size&local_part=$local_part&domain=$domain");

	return "yes"
}

sub block_cracking_notify
{
	my($bc_type) = @_;

	my $sender_host_address = Exim::expand_string('$sender_host_address');
	my $authenticated_id    = Exim::expand_string('$authenticated_id');
	my $script_path		= "";
	my $mid                 = Exim::expand_string('$message_id');
	my $timestamp           = time();

	if ($bc_type eq "script" || $bc_type eq "denied_path") { $script_path = Exim::expand_string('$acl_m_script_path'); }

	open(TQ, ">>/etc/virtual/mail_task.queue");
	print TQ "action=block_cracking&type=$bc_type&authenticated_id=$authenticated_id&script_path=$script_path&sender_host_address=$sender_host_address&log_time=$timestamp\n";
	close(TQ);
	chmod (0660, "/etc/virtual/mail_task.queue");
}

sub log_email
{
	my($lp,$dmn,$sender) = @_;

	#log_str("logging $lp\@$dmn\n");
	my $user = get_domain_owner($dmn);
	if ($user == -1) { return "no"; }

	my $mid = Exim::expand_string('$message_id');
	my $timestamp           = time();

	if ($mid eq "")
	{
		return "yes";
	}

	if ( (@pw = getpwnam($user))  )
	{
		log_bandwidth($pw[2],"type=email&email=$lp\@$dmn&method=incoming&log_time=$timestamp&id=$mid&sender=$sender");
	}

	return "yes";
}

sub save_virtual_user
{
	my $dmn = Exim::expand_string('$domain');
	my $lp  = Exim::expand_string('$local_part');
	my $sender = Exim::expand_string('$sender_address');
	my $usr = "";
	my $pss = "";
	my $entry = "";

	if (!safe_name($dmn) || !safe_name($lp))
	{
		Exim::log_write("save_virtual_user: Invalid username: $lp or domain: $dmn");
		return "no";
	}
	
	open (PASSWD, "/etc/virtual/$dmn/passwd") || return "no";

	while ($entry = <PASSWD>) {
		($usr,$pss) = split(/:/,$entry);
		if ($usr eq $lp) {
			close(PASSWD);
			log_email($lp, $dmn, $sender);
			return "yes";
		}
	}
	close (PASSWD);

	return "no";
}

sub log_bandwidth
{
	my ($uid,$data) = @_;
	my $name = getpwuid($uid);

	if (uid_exempt($uid)) { return; }

	if ($name eq "") { $name = "unknown"; }

	my $bytes = Exim::expand_string('$message_size');

	if ($bytes == -1) { return; }

	my $work_path = $ENV{'PWD'};

	open (BYTES, ">>/etc/virtual/usage/$name.bytes");
	print BYTES "$bytes=$data&path=$work_path\n";
	close(BYTES);
	chmod (0660, "/etc/virtual/usage/$name.bytes");
}

sub is_integer
{
	return $_[0] =~ /^\d+$/
}
sub is_float
{
	return $_[0] =~ /^\d+\.?\d*$/
}

sub get_spam_high_score_drop
{
	my $domain = Exim::expand_string('$acl_m_spam_domain');

	#/etc/virtual/domain.com/filter.conf
	#high_score=7
	#high_score_block=yes

	my $high_score = 1000;
	my $block = "no";

	if (!safe_name($domain))
	{
		Exim::log_write("get_spam_high_score_drop: Invalid domain: $domain");
		return 1000;
	}
	
	if (open (FILTER_CONF, "/etc/virtual/$domain/filter.conf"))
	{
		while ($line = <FILTER_CONF>)
		{
			if ($line =~ m/^high_score=/)
			{
				$line =~ s/\n//;
				my $hs = 1000;
				($dontcare,$hs) = split(/=/, $line);
				if (is_integer($hs) || is_float($hs))
				{
					$high_score = $hs * 10;
				}
			}
			if ($line =~ m/^high_score_block=/)
			{
				$line =~ s/\n//;
				my $b = "no";
				($dontcare,$b) = split(/=/, $line);
				if ($b eq "no")
				{
					#simplest way to not block without having exim.conf changes, is to score unreasonably high
					$high_score = 500000;
					break;
				}
				if ($b eq "yes")
				{
					$block = "yes";
				}
				
			}
		}
		close(FILTER_CONF);
	}

	return $high_score;
}

sub get_spam_subject
{
	my $username = Exim::expand_string('$acl_m_spam_user');
	my $subject = "*****SPAM***** ";

	if ($username eq "nobody") { return $subject; }

	$subject = "";

	#find rewrite_header subject *****SPAM*****
	#if there is no rewrite_header, then don't touch the subject.

	if (open (USER_PREFS, "/home/$username/.spamassassin/user_prefs"))
	{
		$subject = "";    #no rewrite_header subject, they dont want it touched.
		while ($line = <USER_PREFS>)
		{
			if ($line =~ m/^rewrite_header subject /)
			{
				$line =~ s/^rewrite_header subject (.*)\n/$1 /;
				$subject = $line;
				break;
			}
		}
		close(USER_PREFS);
	}

	return $subject;
}

sub get_b64_string
{
	my ($str) = @_;
	
	eval
	{
		require MIME::Base64;
		MIME::Base64->import();
	};

	unless($@)
	{
		my $enc = MIME::Base64::encode_base64($str);
		# an evil newline is added. get rid of it.
		$enc =~ s/\n//;
		return $enc;
	}

	return $str;
}

sub append_record
{
	my $file = shift;
	my ($record) = @_; # Do not allow record splitting.
	$record =~ s/[\n:]//g;
	open(my $fh, '>>', $file) or return "false";
	print $fh "$record:" . time() . "\n";
	close $fh;
	return "true";
}


sub log_str
{
	my ($str) = @_;

	open (LOG, ">> /tmp/test.txt");

	print LOG $str;

	close(LOG);
}

if ( -e "/etc/exim.custom.pl" ) {
	do '/etc/exim.custom.pl';
}
