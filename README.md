# Endpoint analysis for a WordPress webserver

## Objective

To develop a strong foundation in endpoint analysis with a focus on web servers by learning how to interpret log files, investigate compromised assets, and identify malicious behavior. This includes hands-on experience with tools and Linux commands used in endpoint forensics, understanding how WordPress sites can be targeted in cyber attacks, and building practical skills in analyzing system and application-level logs to trace attacker activity.

### Skills Learned

- Gained hands-on experience with endpoint analysis, especially in web server environments
- Became proficient in log analysis, identifying key patterns and filtering out irrelevant data
- Learned how to investigate compromised assets by tracing attacker activity through log files
- Developed familiarity with Linux commands commonly used in forensic investigations
- Gained an understanding of how WordPress sites can be exploited, especially through vulnerable plugins
- Learned to identify signs of remote code execution, webshells, and unauthorized uploads
- Built skills in recognizing what data matters in large logs (e.g., suspicious requests, unusual user-agents, malicious payloads)

### Tools Used

- Kali Linux CLI
- AbuseIPDB.com
- VirtusTotal.com
- Google.com

## Steps

	- For this lab I'll be doing another retired BTLO lab, called "Endpoint Analysis: WordPress"

![image](https://github.com/user-attachments/assets/b22732b1-66be-4687-8a98-34d3dd10b4e3)

	- What is endpoint analysis and what does it entail?

	- Endpoint Analysis:
		○ The process of examining endpoints (e.g., laptops, desktops, servers) to detect, investigate, and respond to signs of compromise, suspicious activity, or security issues. 

	- What it entails:
		○ Data collection
			§ Logs (Windows Event Viewer, Sysmon, .etc.)
			§ Running processes
			§ Network connections
			§ File/system changes
		○ Detection:
			§ Indicators of compromise (IOCs)
			§ Behavioral anomalies (unusual processes or connections)
			§ Signature- or- rule based alerts (EDR/XDR)
		○ Investigation:
			§ Timeline of events
			§ Process tree analysis
			§ Correlation with known threats
		○ Response:
			§ Isolate endpoint
			§ Kill malicious processes
			§ Remove malware
			§ Patch vulnerabilities
		○ Tools Used:
			§ EDR solutions (CrowdStrike, SentinelOne)
			§ Sysinternals Suite (Process Explorer, Autoruns)
			§ PowerShell or Linux command line
			§ SIEM integration


Understanding the scenario:

![image](https://github.com/user-attachments/assets/c9b3255e-2a72-42a4-97be-5c595dbb908b)

	- WordPress:
		○ A popular open-source Content Management System (CMS) that lets users build and manage websites without needing to code. It powers over 40% of all websites. 
		○ It's free and customizable
		○ Massive plugin/theme ecosystem
		○ Beginner and developer friendly 
		○ Supports blogs, business sites, e-commerce, etc.

	- WordPresses widespread use is what makes it such an attractive target to attackers

	- Plugins (WordPress):
		○ Small software add-ons that extend the functionality of a WordPress site without altering the core code.

	- Remote Code Execution (RCE) Vulnerability:
		○ A flaw that allows an attacker to run arbitrary code on a target machine from a remote location, without physical access. 

	- A vulnerable plugin can have bad code that allows user input to be executed as code - opening the door to Remote Code Execution (RCE)

	- Example:
		○ A plugin allows image uploads but doesn’t check file extensions.
		○ Attacker uploads a malicious PHP script disguised as an image → accesses it in the browser → server executes it.

Analyzing Logs:

	- To start the lab I'll need to download the file

	- Once downloaded, I right clicked the desktop and selected the "Open terminal here" option to open a terminal

	- Once I navigated to the directory that the zip file was in, I used the command
		○ "unzip {filename}"
		○ I then entered the password to be able to access the file

![image](https://github.com/user-attachments/assets/df45203a-d05c-429e-b614-7f2d4f82a3a5)

Time Frame of Log File:

	- It's good practice to know the time frame of the log file. 
		○ I need to look at the first and last event

	- The command 'head access.log' will show me the first 10 events that occurred

![image](https://github.com/user-attachments/assets/786d475d-52b0-476b-9c30-20d6ec592d4b)

	- As you can see that first event occurred on January 12th, 2021 at 15:52:41 UTC time. The source IP address was 172.21.0.1

	- To view the last 10 events that occurred, I used the command 'tail access.log'

![image](https://github.com/user-attachments/assets/e2dae947-3209-4102-b53c-d7f56f4ae54c)

	- The last event occurred on the 14th of January, 2021 at 07:46:52 UTC time. It had a source IP address of 172.21.0.1

	- So this is almost 2 days' worth of data that I have.


Source IP Addresses:

	- So based on the first 10 and last 10 events, the only source IP address listed is 172.21.0.1

	- I'm curious if there are any other source Ips in the log file

	- I'll use the command 
		○ "cat access.log | cut -d ' ' -f 1"

	- "cat access.log" outputs the contents of the 'access.log' file
	- | (pipe) sends the output of 'cat' to the next command (which is cut)
	- "cut" extracts specific fields 
	- "d ' ' " sets the delimiter to a space. A delimiter is a character or symbol that separates fields (pieces of data) in a line or file. You set the delimiter using "-d" to tell the tool how to split the line into fields
	- "-f  1" selects field 1 (the first column of the log file)

![image](https://github.com/user-attachments/assets/03065693-2438-4b1a-991f-ede55eb16f77)

	- There is lots of IPs

	- I need to sort it out and do '-d' duplicate.

	- I'll use the up arrow to return to the previous command. Then I'll add " | sort | uniq -c | sort -nr"
		○ So… the whole thing would be "cat access.log | cut -d ' ' -f 1 | sort | uniq -c | sort -nr"

	- " | sort "
		○ This sorts the incoming lines (needed before using uniq)

	- " | uniq -c"
		○ Counts duplicate lines and prefixes each line with the count

	- " | sort -nr"
		○ Sorts the counted output numerically  (-n) and in reverse order (-r)
		○ So the most frequent entries appear at the top

![image](https://github.com/user-attachments/assets/ac98a2d7-7038-4814-b9fe-2b381d3995b9)

	- As you can see there 1,035 hits for the IP 172.21.0.1

	- I can also see how many hits there are for the other IP addresses in this log file

Outputting IP's to File:

	- I want to output this data into a file called "IPs.txt"

	- To do this I can use the same command from earlier using the up arrow. Then I just need to add the command " > IPs.txt" to the end of it
		○ So… "cat access.log | cut -d ' ' -f 1 | sort | uniq -c | sort -nr > IPs.txt"

![image](https://github.com/user-attachments/assets/891252e3-2312-43f5-92cc-4c4d1862fe42)

	- This will output all of the contents into this file called 'IPs.txt'.

	- Now I use the command 'cat IPs.txt' it should output the contents of the file

![image](https://github.com/user-attachments/assets/9f474cfd-9e20-4e85-af6b-d4ee70c01d76)

	- IP address 119.241.22.121 has 249 hits
		○ What is this IP doing?
		○ What activity is associated with this IP?

	- I don't know if this is a legit IP address right now, and it's very easy to get stuck in a time consuming rabbit hole of trying to figure it out

	- This is why "quick win" strategies are so important, and can save you lots of time investigating.

	- Another field that we can check for a "quick win" is the user agent.

Checking for User Agents:

	- User Agent:
		○ A string sent by a browser or client in a web request that tells the server what kind of device, browser, and OS is making the request

	- To check for user agents, I want to use the same "head" command from before. 
		○ I used 'head access.log'

![image](https://github.com/user-attachments/assets/ea22db4b-14bc-435b-9a00-051a8a163c31)

	- This command shows the user agent, as highlighted above
		○ I wonder if there are any other user agents listed in this log file?
		○ Let's find out

	- The user agent is surrounded by quotation marks, so this is a good candidate for a delimiter. 
		○ I can split the log line by '"' so I can easily grab the whole user agent as one clean field.

	- Next I'll use the following command:
		○ 'cat access.log | cut -d '"' -f 1'

![image](https://github.com/user-attachments/assets/0ac07341-e6e1-46ba-a960-88cf26a22678)

	- This returns the source IP and date, so let's try again and go down the fields until I reach the user agent field
		○ This time I'll try field 2

	- 'cat access.log | cut -d '"' -f 2'

![image](https://github.com/user-attachments/assets/19810855-427f-46f0-8297-81d36b8728fb)

	- This shows lots of request, such as GET requests and POST requests

	- I'll just keep going until I get the right field

	- The correct field is 6. 
		○ So the command is 'cat access.log | cut -d '"'  -f 6'

![image](https://github.com/user-attachments/assets/a38da055-eb81-441d-b10e-3e20f2ad6559)

	- Since I now have the correct field, now I can "sort" and "uniq" the file

	- I'll add " | sort | uniq -c | sort -nr"

	- 'cat access.log | cut -d '"' -f 6 | sort | uniq -c | sort -nr'

![image](https://github.com/user-attachments/assets/cb90f7d2-2db4-4d81-a42a-69e0a824574a)
![image](https://github.com/user-attachments/assets/2d123fbc-97f8-465b-84ce-bca758355c63)

	- Now (just like with the Ips earlier), I can see each different user agent, as well as the number of times it was hit

	- I can also see some fields that has a bracket with a date in it 
		○ These aren't user agents, so I need to clean this up a bit
		○ Let's remove this
		○ I'll use the cut command again, the field starts with a bracket ' ] ', we'll use it as a delimiter

	- 'cat access.log | cut -d '"' -f 6 | cut -d '[' -f 1'

![image](https://github.com/user-attachments/assets/c779c087-04b6-4755-a50c-9102e479482e)

	- The output is much cleaner now

	- I'll do the same as I did with the IP addresses, and output this data into a dedicated file called "useragents.txt"

	- 'cat access.log' | cut -d '"' -f 6 | cut -d '[' -f 1 | sort | uniq -c | sort -nr > useragents.txt'

![image](https://github.com/user-attachments/assets/606573b6-5b9b-4c54-868f-32b043d4077e)

	- Now let's analyze the file, so I need to output the contents using 'cat useragents.txt'

![image](https://github.com/user-attachments/assets/b15e6fd9-04c9-4f60-97e7-c99d6cc5d64b)

	- Some interesting things:
		○ 'sqlmap' 
		○ 'WPScan' is a WordPress scanner
		○ Even some python requests

	- The top hit however is the user agent 'Mozilla/5.0 on Linux, and the second hit is on an iPhone

Web traffic:

	- So from previous labs, I know that when looking at web traffic, POST requests are important
		○ POST requests are requests that send data to the server

	- I'll use the 'grep' command to sort through the log file 
		○ The 'grep' command allows us to search the contents of files for specific values or patterns that we are looking for
		○ In this case I want to search for 'POST'

	- So I'll use the command "grep 'POST' access.log"

![image](https://github.com/user-attachments/assets/f3da109e-2e8b-450f-bbe5-d1e07fec144c)

	- So the text 'POST' is now highlighted in red. These are all of the POST requests that happened in the log file.

	- I'll scroll a bit to see if I can find anything that catches my eye. 

![image](https://github.com/user-attachments/assets/a45e3a88-5ade-448b-9672-777956167d51)
![image](https://github.com/user-attachments/assets/cf14a597-6a08-4549-8153-20cf23ab17a8)

	- I notice quite a bit of 403 errors
		○ 403 is a HTTP status code that means the server understands the request, but refuses to authorize it

	- I can also see some 200 status codes (which is very important)
		○ This means the request was successful, and the server returned the expected response 

	- I want to filter out 403 errors
		○ I'll use the previous command, but add some to help sort the output

	- "grep 'POST' access.log | grep -v '403' "
		○ " grep -v " tells grep to exclude a pattern or string

![image](https://github.com/user-attachments/assets/d6c17a43-4f6b-4197-9301-3b0664941ae0)

	- I should no longer see any 403 statuses 

	- So the output is still a garbled mess, so let's sort it even further. Only to source IP addresses as well.
		○ So now essentially we'll see the IP addresses that are associated with successful POST requests 
		○ I'll just the cut command again

	- " grep 'POST' access.log | grep -v '403' | cut -d ' ' -f 1 "

![image](https://github.com/user-attachments/assets/778b87f8-095a-4805-86b4-e5ebf6bc8d15)

	- This returns a smaller amount of IP addresses than earlier, but it's still quite a bit.

	- Now of course, let's use the sort command to make this EVEN cleaner and narrow down it down even more

	- " grep 'POST' access.log | grep -v '403' | cut -d ' ' -f 1 | sort | uniq -c | sort -nr "

![image](https://github.com/user-attachments/assets/12a1b3f4-27af-4473-9a43-29df2917bdc1)

	- The top IP address is the internal IP address 172.21.0.1
		○ It's important to take note of this, but it's not entirely a red flag yet, but it's still worth keeping it on the radar
		○ 172.21.0.1 falls within 172.16.0.0 – 172.31.255.255 → internal use only
		○ These are non-routable on the internet — they belong to internal networks (like Docker, virtual labs, corporate LANs).

	- The second IP address is 103.69.55.212
		○ This could definitely be an IP of interest 
		○ It’s a public IP — routable and traceable on the internet.
		○ 103.69.55.212 is outside any private IP range. This makes it globally routable, and potentially a: Threat actor, Scanner, Exploiting bot
		○ This is much more likely to be malicious

	- I need to some OSINT on this IP address, but first I need to output this data into another file, called "POSTIPs.txt"

	- "  grep 'POST' access.log | grep -v '403' | cut -d ' ' -f 1 | sort | uniq -c | sort -nr > POSTIPs.txt "
		
![image](https://github.com/user-attachments/assets/d1fa47d3-a1fa-4d2a-9ae7-38367312c43a)

	- Now that it's saved in a file, I'll use the website "abuseipdb.com" to perform some OSINT on the IP 103.69.55.212

![image](https://github.com/user-attachments/assets/40308033-ddcf-44ee-a676-9a723c3b597e)
![image](https://github.com/user-attachments/assets/c33c22a7-4b6a-4644-8f02-a962cf2baede)

	- It wasn't found in the database, so there is no reports on it
		○ However the Internet Service Provider is "Quewu Co. Ltd."
		○ The country/city of origin is Taipei, Taiwan

	- Now I'll do the same using "VirusTotal.com"

![image](https://github.com/user-attachments/assets/d3abfe9a-23ad-4aa7-9f44-c00dad768792)
![image](https://github.com/user-attachments/assets/9c88d53f-861b-4ec0-b668-bf92ce9e91a9)

	- It seems clean on here as well


	- Now I want to actually search through the log file itself to find activity related to 103.69.55.217
		○ I'll use the grep command for this

	- " grep '103.69.55.212' access.log "

![image](https://github.com/user-attachments/assets/c63b9bb2-a5db-43dc-a570-94c64cfa616d)
![image](https://github.com/user-attachments/assets/576b0ee7-a861-49a7-9f01-fbdfddb3b38c)

	- We know that it was though the word press site was compromised due to a vulnerable plugin, and if we look at this third entry for 103.69.55.212, I can see a GET request to a plugin called "contact-form-7"
		○ This could be the vulnerable plugin 

	- Or it could be this one below, named "simple-file-list"

![image](https://github.com/user-attachments/assets/cb9cf67e-aa34-4148-9a79-37c1087b2c47)

	- I'll do some OSINT on these plugins to see if there are any vulnerabilities that are related to them
		○ I can do this with simple google search

![image](https://github.com/user-attachments/assets/68007929-68c6-4288-8900-b75a54096516)
![image](https://github.com/user-attachments/assets/a594e0c6-9562-4e98-8148-6ca174d5d9fb)

	- There are multiple results, I can see from some of the sites that it has a CVE of 2020-35489

![image](https://github.com/user-attachments/assets/1ccb64f0-ae2a-43c6-98a4-664daf58cff1)

	- Now I'll do a Google search for "simple-file-list"
		○ I see multiple results for this as well

![image](https://github.com/user-attachments/assets/c90a1726-577b-43dd-a08d-cc3e358e2d7f)
![image](https://github.com/user-attachments/assets/f32bd162-b9ef-45cd-a4f2-8fadae591af4)
![image](https://github.com/user-attachments/assets/ad55ae4d-813c-4f86-9937-2d3016de44ff)

	- So I can see this is for an arbitrary file upload
		○ I can even view the code on how to exploit the vulnerability

![image](https://github.com/user-attachments/assets/8105ba03-7ec5-4825-9e98-5373394d0210)

	- Notice it it’s a pre-authenticated remote code execution 


	- Now I know that these are exploits, so I'll go back, and search for them in the terminal
		○ I'll use grep to search for "contact" "form" and "simple"

	- " grep 'POST' access.log | grep -i 'contact' "
		○ " grep -i " ignores case sensitivity 

![image](https://github.com/user-attachments/assets/65b32a78-fb41-4205-9353-186bb95ab0bb)

	- This is all traffic related to the contact-form-7 plugin

	- I know based on the scenario, that this vulnerability (RCE) was related to file uploads
		○ Were there any file uploads towards this plugin?

	- To find this out, I simply need to like at the URL that was posted
		○ It seems to be all contact forms for feedback in the URL
		○ There seems to be no file uploads towards this plugin

	- I'll check simple-file-list

	- " grep 'POST' access.log | grep -i 'simple' "

![image](https://github.com/user-attachments/assets/a89d232f-831a-46d0-a94d-c49b6d0eda6f)
![image](https://github.com/user-attachments/assets/8d663ed3-1ff4-4750-8e6d-573bc490d8b0)

	- I do  see a file named "fre34k.php" underneath uploads in the URL

	- There is also another IP address: 119.241.22.121, and it seems to be using a Python request user agent
		○ "Python request user agent" refers to a user agent string sent by scripts using the Python requests library.


	- This makes me curious about what activities is associated with the address 119.241.22.121
		○ Let's search for this using grep

![image](https://github.com/user-attachments/assets/944f3165-ea9c-40b9-a93b-cbc78d71a73a)

	- The first event take place on 14th of January, 2021 at 05:43:34 UTC time. I can also see that it was interacting with the plugin contact-form-7 and of course the plugin simple-file-list

	- If I scroll down, I can see that it's performing a lot of GET requests 

![image](https://github.com/user-attachments/assets/05438b12-8ac6-4145-8f5a-a5f8b0007f0d)

	- I can see that there are a lot of GET requests for some accounts
		○ It also seems to be using an iPhone, but this could be spoofed

	- If I keep scrolling, I also see a successful POST request for a log on for "itsec-hb-token=adminlogin"
		○ This occurred on January 14th, 2021 at 05:54:14

![image](https://github.com/user-attachments/assets/52da2a7b-7852-445b-8bdc-30b469ece1aa)

	- Maybe this IP found a token that grants them access. 
		○ A token is a secret value (like a temporary password) that proves your identity or grants access to something
		○ This means:
			§ The attacker discovered or stole a valid token (maybe through guessing, interception, or scanning)
			§ They are now using it in POST requests to:
			§ Bypass login
			§ Access protected resources
			§ Upload data or issue commands
			
	- I can also see that this IP also used the user agent "WPscan"

![image](https://github.com/user-attachments/assets/d773ae0a-2c99-4330-a5f0-7ea9baf5350c)

	- At the bottom if the output I can also see a POST request from this external IP at 6:26:53, then immediately after that I see a GET request and a "fr34k.png" file

![image](https://github.com/user-attachments/assets/c990233d-da66-4e2a-a3ce-9be50fbe946a)

	- Based on the OSINT info on this exploit, it will automatically rename .png to .php

	- I need to perform some OSINT on this IP address
		○ I'll use "abuseipdb.com" first

![image](https://github.com/user-attachments/assets/2de28888-4b9f-436e-8a88-76e7785b64e3)

	- There are no reports on this IP, but it seems to be located in Japan
		○ The ISP is BIGGLOBE Inc. 

	- Now let's check "Virustotal.com"

![image](https://github.com/user-attachments/assets/c2ebf9a2-1c72-4919-b861-fac9c327aa8c)

	- There are no security vendors that have flagged this IP address as malicious 


	- I need to go back to the terminal and check when these plugins were installed or activated
		○ I'll use the grep command once again

	- " grep -i 'contact-form-7' access.log " 
		○ Now I need to scroll all the way up

![image](https://github.com/user-attachments/assets/2710e67d-1a91-473c-b8dc-68c1dd2d48f2)

	- The first event is a GET request that has an action that equals activate 

	- So this plugin was activated on January 12th, 2021 at 15:57:07 UTC time

	- Now I'll do the same for simple-file-list
		○ " grep -i 'simple-file-list' access.log "

![image](https://github.com/user-attachments/assets/cba9feba-e5e2-437f-a1cb-60c94b058638)

	- Again the first event is a  GET request with an action that equals activate 

	- This plugin was activated on January 12th, 2021 at 15:56:41 UTC time


	- I think I've gathered enough information on this vulnerability, now I need to recap the findings in my ending notes.






Recap Notes:

January 12 @ 15:56:41 UTC
	- Plugin: contact-form-7 was activated

January 12 @ 15:57:07 UTC
	- Plugin: simple-file-list was activated

Both plugins have vulnerabilities to RCE
	- ' contact-form-7 ' - Vulnerable  versions <= 5.3.1
	- ' simple-file-list ' - Vulnerable versions <= 4.2.2

First external IP activity 
	- January 14th @ 05:42:34 UTC
	- IP: 119.241.22.121 - Japan
	- Interacting with both plugins
	- Crawling file paths on 172.21.0.3

January 14th @ 05:54:14 UTC
	- 119.241.22.121 Identified Token: adminlogin
	- Full URI: wp-login.php?itsec-hb-token=adminlogin

January 14 @ 06:01:41 UTC
	- IP: 119.241.22.1212 - Japan
	- Used tool WPScan (WordPress Scanner)

January 14th @ 06:08:31 UTC
	- IP: 103.69.55.212 - Taiwan
	- Crawling plugins on 172.21.0.3

January 14th @ 06:26:53 UTC
	- IP: 119.241.22.121 - Japan
	- Exploited plugin: simple-file-list
	- Uploaded file named: fr34k.png

GET Request towards fr34k.php (renamed seconds after automatically)
	- From IP: 103.69.55.212 - Taiwan

Last Observed Activity
	- IP: 119.241.22.121 - Japan
	- January 14 @ 06:26:53 UTC
	- IP: 103.69.55.212 - Taiwan
	- January 14 @ 06:30:11 UTC

Total Duration: 47 Minutes and 37 Seconds






Answers to Questions:

![image](https://github.com/user-attachments/assets/ee5322d6-5940-4eed-8f6d-59495f36dd85)

	- For answer 1, we know found this earlier when searching through the activity of 119.241.22.121

	- For answer 2, we can find this by looking at the user agents. We can just look at our uderagents.txt file (at the bottom).

	- We found the answer 3 earlier when performing OSINT on the plugin.

	- The answer to question 4 we found by also performing OSINT on the plugin. I also needed to provide the version.

	- The answer to the question is interesting. I already grepped the .php file, so I'll need to look at the last entry.

![image](https://github.com/user-attachments/assets/3f0d810f-a106-4422-b31f-b43d68167b6f)

		○ It was a 404 response code 

