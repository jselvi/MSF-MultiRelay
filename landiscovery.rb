# landiscovery.rb
#
# meterpreter-script to discovery alive systems on the lan
#
# Written by Jose Selvi (jselvi{_at_}pentester.es)
# v.1.1 2011-03-09

# Fingerprintig & Fu Selection
# Based on http://blog.commandlinekungfu.com/
def whatfu()
	# Return variables
	shell = ""
	query = ""
	regex = ""
	fu = [shell,query,regex]
	# Getting OS
	os = client.sys.config.sysinfo['OS']
	# Depend on OS...
	case os
		when /(?i)windows/
			print_status "WINDOWS KUNG FU..."
			shell = "cmd.exe"
			query = "FOR /L %i in (1,1,255) do (@START /B ping #NET#.%i -w 1 -n 1 > NUL\necho %i\narp -a | find /V \"00-00-00-00-00-00\" | find \" #NET#.\")\nexit\n"
			regex = "#NET#.[0-9]+"
			fu = [shell,query,regex]

		when /(?i)linux/
			print_status "LINUX KUNG FU..."
			shell = "sh"
			query = "for i in `seq 1 255`\ndo\nping -c 1 #NET#.$i >/dev/null &\n/usr/sbin/arp -na | grep '\(#NET#' |egrep \"[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+\"\ndone\nexit\n"
			regex = "#NET#.[0-9]+"
			fu = [shell,query,regex]
		else
			fu = false
	end
	# Return result
	return fu
end

# Kung Fu LanDiscovery
def landiscovery()
	# Alive IPs Array
	aliveips = []
	# Getting Fu...
	fu = whatfu()
	if not fu
		print_error "OS UNSUPPORTED!"
		print_error "I DON'T KNOW THIS FU..."
		return []
	end
	mastershell = fu[0]
	masterquery = fu[1]
	masterregex = fu[2]
	# Get Local Interfaces
	client.net.config.interfaces.each do |iface|
	# Discovery for each LAN
	if not iface.mac_name =~ /Loopback/
		# Convert IP and Net
		v = iface.ip.split('.') 
		net = v[0].to_s + "." + v[1].to_s + "." + v[2].to_s
		# Sustitute #NET# for ip
		shell = mastershell
		query = masterquery.gsub("#NET#",net)
        	regex = masterregex.gsub("#NET#",net)
		# Execute Shell
		c = client.sys.process.execute(shell, nil, {'Hidden' => true, 'Channelized' => true})
		# Execute Fu
		c.channel.write(query)
		# Get Results
		text = c.channel.read
		while text
			text.each do |line|
				ip = line.scan(/#{regex}/).to_s
				if ip and ip.match(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
					aliveips |= ip.to_a
				end
			end
			text = c.channel.read
		end
		c.channel.close
	end
	end
	return aliveips
end

# Main
hosts = landiscovery()
hosts.each do |x|
	print "#{x}\n"
end
raise Rex::Script::Completed

