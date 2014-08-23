# portscan.rb
#
# meterpreter-script to portscan hosts
#
# Written by Jose Selvi (jselvi{_at_}pentester.es)
# v.1.1 2011-03-09

@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false, "Help menu." ],
        "-t" => [ true,  "The target IP address"]
)

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
			query = "FOR %i in (#PORTS#) do @netsh diag connect iphost #IP# %i | find \"\[%i\]\"\nexit\n"
			regex = "\\[[0-9]+\\]"
			fu = [shell,query,regex]
		else
			print_status "LINUX KUNG FU..."
			shell = "sh"
			query = "PPID=$$\nfor i in #PORTS#\ndo\nftp #IP# $i 1>/dev/null 2>/dev/null &\ndone\nnetstat -n | grep \" #IP#:\" | cut -d':' -f 3 | cut -d' ' -f 1 | sort | uniq\nkillall ftp 1>/dev/null 2>/dev/null\nexit\n"
			regex = "[0-9]+"
			fu = [shell,query,regex]
			#fu = false
	end
	# Return result
	return fu
end

# 
def portscan(ip,ports)
	# Alive Ports Array
	aliveports = []
	# Getting Fu...
	fu = whatfu()
	if not fu
		print_error "OS UNSUPPORTED!"
		print_error "I DON'T KNOW THIS FU..."
		return []
	end
	mastershell = fu[0].gsub("#IP#",ip)
	masterquery = fu[1].gsub("#IP#",ip)
	masterregex = fu[2].gsub("#IP#",ip)
	# Set Query & Regex
	shell = mastershell.gsub("#PORTS#",ports)
	query = masterquery.gsub("#PORTS#",ports)
	regex = masterregex.gsub("#PORTS#",ports)
	# Execute Shell
	c = client.sys.process.execute(shell, nil, {'Hidden' => true, 'Channelized' => true})
	# Execute Fu
	c.channel.write(query)
	# Get Results
        text = c.channel.read
        while text
		text.each do |line|
        		port = line.scan(/#{regex}/).to_s.scan(/[0-9]+/).to_s
			# If port exists and it's a number... Open Port!
        		if port and port.match(/[0-9]+/)
                		aliveports |= port.to_a
        		end
		end
        	text = c.channel.read
        end
        c.channel.close

	return aliveports
end

# Parse Arguments
ip = 'none'
@@exec_opts.parse(args) { |opt, idx, val|
        case opt
	when "-t"
		ip = val
        end
}

# Main
if ip == 'none'
	print_line "Meterpreter Script for performing a PortScan with Fu Techniques."
        print_line(@@exec_opts.usage)
        raise Rex::Script::Completed
end
top100ports = "7 9 13 21 22 23 25 26 37 53 79 80 81 88 106 110 111 113 119 135 139 143 144 179 199 389 427 443 444 445 465 513 514 515 543 544 548 554 587 631 646 873 990 993 995 1025 1026 1027 1028 1029 1110 1433 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5051 5060 5101 5190 5357 5432 5631 5666 5800 5900 6000 6001 6646 7070 8000 8008 8009 8080 8081 8443 8888 9100 9999 10000 32768 49152 49153 49154 49155 49156 49157"
#top100ports = "444 445 446"
ports = portscan(ip,top100ports)
ports.each do |x|
	print "#{x}\n"
end
raise Rex::Script::Completed

