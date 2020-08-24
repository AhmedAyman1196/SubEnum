import os , sys , re , subprocess , shlex
from termcolor import colored

# ~~~~~~~~~~~~~~~~~~~~~ Functions ~~~~~~~~~~~~~~~~~~~~~

def run_command(command):
	res= [] 
	process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=None)
	while True:
		output = process.stdout.readline()
		if output == b'' and process.poll() is not None:
			break
		if output:
			res.append(output.decode("utf-8").strip())
	rc = process.poll()
	return res

def checkURL(URL):
	regex = re.compile(
		r'^(?:http|ftp)s?://' # http:// or https://
		r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
		r'localhost|' #localhost...
		r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
		r'(?::\d+)?' # optional port
		r'(?:/?|[/?]\S+)$', re.IGNORECASE)
	return re.match(regex, URL) is not None

def WAFCheck(URL):
	command = "wafw00f "+ URL 
	res = run_command(command)
	return res

def gitCheck(URL):
	run_command("mkdir gitDump")
	command = "/opt/gitdumper/gitdumper.sh " + URL +"/.git/ gitDump/"
	res = run_command(command)
	return res

def WPcheck(URL):
	command = "wpscan --url " + URL
	res = run_command(command)
	return res

def Wayback(URL):
	command = 'echo '+URL+' | /opt/waybackurls/main > waybackurls.txt'
	res = run_command(command)
	return res

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 							Main 		
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# ~~~~~~~~~~~~~~~~~~~~~ Argument Check ~~~~~~~~~~~~~~~~~~~~~

#check number of arguments
if len(sys.argv) != 2:
	print(colored("Please Enter only one argument"))
	sys.exit()
# check URL format
elif not checkURL(sys.argv[1]):
	print(colored("Wrong URL Format, Enter with this format\nhttp(s)://target.com"))
	sys.exit()


print(colored("\n------------------------------", 'red'))
print(colored("Started Enumeration",'green'))
print(colored("------------------------------\n",'red'))

URL = sys.argv[1]


# ~~~~~~~~~~~~~~~~~~~~~ WAF Check ~~~~~~~~~~~~~~~~~~~~~
print(colored("Checking WAF ...\n\n",'green'))
WAF = WAFCheck(URL)
for i in WAF :
	print(i)

# ~~~~~~~~~~~~~~~~~~~~~ Git check ~~~~~~~~~~~~~~~~~~~~~
print(colored("\n\nChecking Git Repo ...\n\n",'green'))
git = gitCheck(URL)
for i in git :
	print(i)

# ~~~~~~~~~~~~~~~~~~~~~ WordPress check ~~~~~~~~~~~~~~~~~~~~~
print(colored("\n\nChecking Wordpress ...\n\n",'green'))
WP = WPcheck(URL)
for i in WP :
	print(i)

# # ~~~~~~~~~~~~~~~~~~~~~ Wayback machine ~~~~~~~~~~~~~~~~~~~~~
# print(colored("Checking wayback machine ...\n\n",'green'))
# WB = Wayback(URL)
# for i in WB :
# 	print(i)




