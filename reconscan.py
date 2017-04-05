#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket

# Todo:
# turn the enum into an actual enum
# Handle UDP scans... Currently none of that is automated and easily could be.
#     SNMP, SMB are good examples

# Add mysql nmap-script
# Change replace to sed:
# sed 's|literal_pattern|replacement_string|g'

start = time.time()

ip_output_dir = ""

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Creates a function for multiprocessing. Several things at once.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def connect_to_port(ip_address, port, service):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)

    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip_address, "ftp-connect", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-connect", total_communication)
    elif service == "ssh":
        total_communication = banner
        write_to_file(ip_address, "ssh-connect", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner +  user +  password
        write_to_file(ip_address, "pop3-connect", total_communication)
    s.close()

def write_to_file(ip_address, enum_type, data, port="0"):

    file_path_linux = ip_output_dir + "/mapping-linux.md"
    file_path_windows = ip_output_dir + "/mapping-windows.md"
    paths = [file_path_linux, file_path_windows]
    print bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n" + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC

    for path in paths:
        if enum_type == "syn_scan":
            subprocess.check_output("replace INSERT_SYN_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "portscan":
            subprocess.check_output("replace INSERT_TCP_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "dirb":
            subprocess.check_output("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "nikto":
            subprocess.check_output("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "ftp-connect":
            subprocess.check_output("replace INSERTFTPTEST \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "smtp-connect":
            subprocess.check_output("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "ssh-connect":
            subprocess.check_output("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "pop3-connect":
            subprocess.check_output("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "curl":
            subprocess.check_output("replace INSERTCURLHEADER \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "udp_scan":
            subprocess.check_output("replace INSERT_UDP_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "script_scan":
            subprocess.check_output("replace INSERT_SCRIPT_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "full_port_scan":
            subprocess.check_output("replace INSERT_FULL_PORT_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "monster_scan":
            subprocess.check_output("replace INSERT_MONSTER_SCAN \"" + data + "\"  -- " + path, shell=True)
        elif enum_type == "smb_nmap":
            string_wtih_port = "replace INSERT_SMB_SCAN_%s \"%s\"  -- %s" % (port, data, path)
            subprocess.check_output(string_wtih_port, shell=True)
        elif enum_type == "smb_enum":
            string_wtih_port = "replace INSERT_ENUM4LINUX_SCAN_%s \"%s\"  -- %s" % (port, data, path)
            subprocess.check_output(string_wtih_port, shell=True)
        else:
            print "Incorrect enum type " + enum_type
    return

def dirb(ip_address, port, url_start):
    print bcolors.HEADER + "INFO: Starting dirb scan for " + ip_address + bcolors.ENDC
    DIRBSCAN = "dirb " + url_start + "://" + ip_address + ":" + port + " -o " + ip_output_dir + "dirb-" + ip_address + ".txt -r"
    #DIRBSCAN = "dirb %s://%s:%s -o /root/oscp/exam/%s/dirb-%s.txt -r" % (url_start, ip_address, port, ip_address, ip_address)
    print bcolors.HEADER + DIRBSCAN + bcolors.ENDC
    results_dirb = subprocess.check_output(DIRBSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with dirb scan for " + ip_address + bcolors.ENDC
    print results_dirb
    write_to_file(ip_address, "dirb", results_dirb)
    return

def nikto(ip_address, port, url_start):
    print bcolors.HEADER + "INFO: Starting nikto scan for " + ip_address + bcolors.ENDC
    NIKTOSCAN = "nikto -h %s://%s -o %s/nikto-%s-%s.txt" % (url_start, ip_address, ip_output_dir, url_start, ip_address)
    print bcolors.HEADER + NIKTOSCAN + bcolors.ENDC
    results_nikto = subprocess.check_output(NIKTOSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with NIKTO-scan for " + ip_address + bcolors.ENDC
    print results_nikto
    write_to_file(ip_address, "nikto", results_nikto)
    return

def httpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"http"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"http"))
    nikto_process.start()

    CURLSCAN = "curl -I http://%s" % (ip_address)
    print bcolors.HEADER + CURLSCAN + bcolors.END
    curl_results = subprocess.check_output(CURLSCAN, shell=True)
    write_to_file(ip_address, "curl", curl_results)
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN %s/%s_http.nmap %s" % (port, ip_output_dir, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCAN + bcolors.ENDC

    http_results = subprocess.check_output(HTTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTP-SCAN for " + ip_address + bcolors.ENDC
    print http_results
    return

def httpsEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap web script scan for " + ip_address + ":" + port + bcolors.ENDC

    dirb_process = multiprocessing.Process(target=dirb, args=(ip_address,port,"https"))
    dirb_process.start()
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address,port,"https"))
    nikto_process.start()

    SSLSCAN = "sslscan %s:%s >> %s/ssl_scan_%s" % (ip_address, port, ip_output_dir, ip_address)
    print bcolors.HEADER + SSLSCAN + bcolors.ENDC
    ssl_results = subprocess.check_output(SSLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with SSLSCAN for " + ip_address + bcolors.ENDC

    HTTPSCANS = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN %s/%s_http.nmap %s" % (port, ip_output_dir, ip_address, ip_address)
    print bcolors.HEADER + HTTPSCANS + bcolors.ENDC
    https_results = subprocess.check_output(HTTPSCANS, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with HTTPS-scan for " + ip_address + bcolors.ENDC
    print https_results
    return

def mssqlEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port + bcolors.ENDC
    MSSQLSCAN = "nmap -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN %s/mssql_%s.nmap %s" % (port, ip_output_dir, ip_address, ip_address)
    print bcolors.HEADER + MSSQLSCAN + bcolors.ENDC
    mssql_results = subprocess.check_output(MSSQLSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with MSSQL-scan for " + ip_address + bcolors.ENDC
    print mssql_results
    return

def smtpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected smtp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = "nmap -sV -Pn -p %s --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 %s -oN %s/smtp_%s.nmap" % (port, ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + SMTPSCAN + bcolors.ENDC
    smtp_results = subprocess.check_output(SMTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMTP-scan for " + ip_address + bcolors.ENDC
    print smtp_results
    # write_to_file(ip_address, "smtp", smtp_results)
    return

def smbNmap(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    smbNmap = "nmap -p %s --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse %s -oN %s/smb_%s.nmap" % (port, ip_address, ip_output_dir, ip_address)
    smbNmap_results = subprocess.check_output(smbNmap, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with SMB-Nmap-scan for " + ip_address + bcolors.ENDC
    print smbNmap_results
    write_to_file(ip_address, "smb_nmap", smbNmap_results, port)
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    enum4linux = "enum4linux -a %s > %s/enum4linux_%s" % (ip_address, ip_output_dir, ip_address)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + ip_address + bcolors.ENDC
    print enum4linux_results
    write_to_file(ip_address,"smb_enum", enum4linux_results, port)
    return

def snmpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected snmp on " + ip_address + ":" + port + bcolors.ENDC
    snmpdetect = 0
    ip_address = sys.argv[1]

    ONESIXONESCAN = "onesixtyone %s" % (ip_address)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

    if results != "":
        if "Windows" in results:
            results = results.split("Software: ")[1]
            snmpdetect = 1
        elif "Linux" in results:
            results = results.split("[public] ")[1]
            snmpdetect = 1
        if snmpdetect == 1:
            print "[*] SNMP running on " + ip_address + "; OS Detect: " + results
            SNMPWALK = "snmpwalk -c public -v1 %s 1 > results/%s_snmpwalk.txt" % (ip_address, ip_address)
            results = subprocess.check_output(SNMPWALK, shell=True)

    NMAPSCAN = "nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes -oN '%s/snmp_%s.nmap' %s" % (ip_output_dir, ip_address, ip_address)
    results = subprocess.check_output(NMAPSCAN, shell=True)
    print results
    return

def ftpEnum(ip_address, port):
    print bcolors.HEADER + "INFO: Detected ftp on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN '%s/ftp_%s.nmap' %s" % (port, ip_output_dir, ip_address, ip_address)
    print bcolors.HEADER + FTPSCAN + bcolors.ENDC
    results_ftp = subprocess.check_output(FTPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with FTP-Nmap-scan for " + ip_address + bcolors.ENDC
    print results_ftp
    return

def udpScan(ip_address):
    print bcolors.HEADER + "INFO: Detected UDP on " + ip_address + bcolors.ENDC

    #first, run a super simple scan you can use to parse results
    SIMPLE_UDP_SCAN = "nmap -sU --top-ports 200 %s" % (ip_address)
    print bcolors.HEADER + SIMPLE_UDP_SCAN + bcolors.ENDC
    simple_udpscan_results = subprocess.check_output(SIMPLE_UDP_SCAN, shell=True)

    UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/udp_%s.nmap' %s"  % (ip_output_dir, ip_address, ip_address)
    print bcolors.HEADER + UDPSCAN + bcolors.ENDC
    udpscan_results = subprocess.check_output(UDPSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with UDP-Nmap scan for " + ip_address + bcolors.ENDC
    print udpscan_results
    write_to_file(ip_address, "udp_scan", udpscan_results)
    UNICORNSCAN = "unicornscan -mU -v -I %s > %s/unicorn_udp_%s.txt" % (ip_address, ip_output_dir, ip_address)
    # Note - redirected output into a file. There is nothing to print here.
    unicornscan_results = subprocess.check_output(UNICORNSCAN, shell=True)
    print bcolors.OKGREEN + "INFO: CHECK FILE - Finished with UNICORNSCAN for " + ip_address + bcolors.ENDC

    return simple_udpscan_results


def sshScan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected SSH on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "ssh")

def pop3Scan(ip_address, port):
    print bcolors.HEADER + "INFO: Detected POP3 on " + ip_address + ":" + port  + bcolors.ENDC
    connect_to_port(ip_address, port, "pop3")

def basicNmapTcpScans (ip_address):
    ip_address = ip_address.strip()
    print bcolors.OKGREEN + "INFO: Running general TCP/UDP nmap scans for " + ip_address + bcolors.ENDC

    # run the first nmap (syn) scan
    SYN_SCAN = "nmap -sS %s -oN '%s/syn_%s.nmap'" % (ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + SYN_SCAN + bcolors.ENDC
    results = subprocess.check_output(SYN_SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC Nmap-scan for " + ip_address + bcolors.ENDC
    print results
    write_to_file(ip_address, "syn_scan", results)

    # run the basic TCP nmap scan
    TCP_SCAN = "nmap -sV -O %s -oN '%s/%s.nmap'" % (ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + TCP_SCAN + bcolors.ENDC
    results_to_parse = subprocess.check_output(TCP_SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with BASIC TCP Nmap-scan for " + ip_address + bcolors.ENDC
    print results_to_parse
    write_to_file(ip_address, "portscan", results_to_parse)

    return results_to_parse

def advancedNmapScans(ip_address):
    # run the script nmap scan
    SCRIPT_SCAN = "nmap -sC %s -oN '%s/default_script_%s.nmap'" % (ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + SCRIPT_SCAN + bcolors.ENDC
    results = subprocess.check_output(SCRIPT_SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with Default Script Nmap-scan for " + ip_address + bcolors.ENDC
    print results
    write_to_file(ip_address, "script_scan", results)

    # run a full port nmap scan
    FULL_PORT_SCAN = "nmap -p- %s -oN '%s/full_port_%s.nmap'" % (ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + FULL_PORT_SCAN + bcolors.ENDC
    results = subprocess.check_output(FULL_PORT_SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with Full Port Nmap-scan for " + ip_address + bcolors.ENDC
    print results
    write_to_file(ip_address, "full_port_scan", results)

    # run the "monster scan"
    MONSTER_SCAN = "nmap -p- -A -T4 -sC %s -oN '%s/monster_%s.nmap'" % (ip_address, ip_output_dir, ip_address)
    print bcolors.HEADER + MONSTER_SCAN + bcolors.ENDC
    results = subprocess.check_output(MONSTER_SCAN, shell=True)
    print bcolors.OKGREEN + "INFO: RESULT BELOW - Finished with Monster Nmap-scan for " + ip_address + bcolors.ENDC
    print results
    write_to_file(ip_address, "monster_scan", results)

def parseResults(results_to_parse, protocol):
    lines = results_to_parse.split("\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if (protocol in line) and ("open" in line) and not ("Discovered" in line):
            # print line
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit= line.split(" ")
            service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port/proto
            # print port
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            # print ports
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)

    return serv_dict

def furtherEnum(ip_address, serv_dict):

   # go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if (serv == "http") or (serv == "http-proxy") or (serv == "http-alt") or (serv == "http?"):
            for port in ports:
                port = port.split("/")[0]
                httpEnum(ip_address, port)
                #multProc(httpEnum, ip_address, port)
        elif (serv == "ssl/http") or ("https" == serv) or ("https?" == serv):
            for port in ports:
                port = port.split("/")[0]
                httpsEnum(ip_address, port)
                # multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                smtpEnum(ip_address, port)
                #multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                ftpEnum(ip_address, port)
                #multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                smbEnum(ip_address, port)
                #multProc(smbEnum, ip_address, port)
                smbNmap(ip_address, port)
                #multProc(smbNmap, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                mssqlEnum(ip_address, port)
                #multProc(mssqlEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                sshScan(ip_address, port)
                #multProc(sshScan, ip_address, port)
        elif "snmp" in serv:
            for port in ports:
                port = port.split("/")[0]
                snmpEnum(ip_address, port)
                #multProc(snmpEnum, ip_address, port)
  #     elif ("domain" in serv):
    #  for port in ports:
     #    port = port.split("/")[0]
     #    multProc(dnsEnum, ip_address, port)

    return

def scan(ip_address):
    # first, run the basic TCP Nmap scans and get our list of processes
    tcp_nmap_results = basicNmapTcpScans(ip_address)

    # then, run UDP nmap scans and get our list of processes
    udp_nmap_results = udpScan(ip_address)

    # next, run the intense TCP Nmap Scans
    advancedNmapScans(ip_address)

    # then, check for other TCP enumeration we can do
    serv_dict = parseResults(tcp_nmap_results, "tcp")
    furtherEnum(ip_address, serv_dict)

    # finally, check for other UDP enumeration we can do
    serv_dict = parseResults(udp_nmap_results, "udp")
    furtherEnum(ip_address, serv_dict)



print bcolors.HEADER
print "------------------------------------------------------------"
print "!!!!                      RECON SCAN                   !!!!!"
print "!!!!            A multi-process service scanner        !!!!!"
print "!!!!        dirb, nikto, ftp, ssh, mssql, pop3, tcp    !!!!!"
print "!!!!                    udp, smtp, smb                 !!!!!"
print "------------------------------------------------------------"



if len(sys.argv) < 2:
    print ""
    print "Usage: python reconscan.py <ip> <ip> <ip>"
    print "Example: python reconscan.py 192.168.1.101 192.168.1.102"
    print ""
    print "############################################################"
    pass
    sys.exit()

print bcolors.ENDC

if __name__=='__main__':

    # Setting ip targets
    recon_dir_path = "/root/Dropbox/OSCP_t2/enumeration/recon_script/"
    win_template_path = "/root/Dropbox/OSCP_t2/scripts/recon/bobloblaw/windows-template.md"
    linux_template_path = "/root/Dropbox/OSCP_t2/scripts/recon/bobloblaw/linux-template.md"

    targets = sys.argv
    targets.pop(0)

    dirs = os.listdir(recon_dir_path)
    for scanip in targets:
        scanip = scanip.rstrip()
        ip_output_dir = recon_dir_path + scanip
        if not scanip in dirs:
            print bcolors.HEADER + "INFO: No folder was found for " + scanip + ". Setting up folder." + bcolors.ENDC
            subprocess.check_output("mkdir " + ip_output_dir, shell=True)
            subprocess.check_output("mkdir " + ip_output_dir + "/exploits", shell=True)
            subprocess.check_output("mkdir " + ip_output_dir + "/privesc", shell=True)
            print bcolors.OKGREEN + "INFO: Folder created here: " + ip_output_dir + bcolors.ENDC
            subprocess.check_output("cp " + win_template_path + " " + ip_output_dir + "/mapping-windows.md", shell=True)
            subprocess.check_output("cp " + linux_template_path + " " + ip_output_dir + "/mapping-linux.md", shell=True)
            print bcolors.OKGREEN + "INFO: Added pentesting templates: " + ip_output_dir + bcolors.ENDC
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' " + ip_output_dir + "/mapping-windows.md", shell=True)
            subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' " + ip_output_dir + "/mapping-linux.md", shell=True)

        scan(scanip)
        #p = multiprocessing.Process(target=nmapScan, args=(scanip,))
        #p.start()
