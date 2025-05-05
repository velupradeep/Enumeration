## DEVELOPED BY

```
NAME : PRADEEP V
REG NO : 212223240119
DEPT : B-TECH AIML 

```


# Enumeration
Enumeration Techniques

# Explore Google hacking and enumeration 

# AIM:

To use Google for gathering information and perform enumeration of targets

## STEPS:

### Step 1:

Install kali linux either in partition or virtual box or in live mode

### Step 2:

Investigate on the various Google hacking keywords and enumeration tools as follows:


### Step 3:
Open terminal and try execute some kali linux commands

## Pen Test Tools Categories:  

Following Categories of pen test tools are identified:
Information Gathering.

Google Hacking:

Google hacking, also known as Google dorking, is a technique that involves using advanced operators to perform targeted searches on Google. These operators can be used to search for specific types of information, such as sensitive data that may have been inadvertently exposed on the web. Here are some advanced operators that can be used for Google hacking:

site: This operator allows you to search for pages that are within a specific website or domain. For example, "site:example.com" would search for pages that are on the example.com domain.
Following searches for all the sites that is in the domain yahoo.com

## OUTPUT :

![1](https://github.com/user-attachments/assets/036eea96-d531-4d34-8e76-e7ea8f928707)


filetype: This operator allows you to search for files of a specific type. For example, "filetype:pdf" would search for all PDF files.
Following searches for pdf file in the domain yahoo.com

## OUTPUT :
![2](https://github.com/user-attachments/assets/68dddd84-51aa-4210-8ea1-03d5b3630ced)



intext: This operator allows you to search for pages that contain specific text within the body of the page. For example, "intext:password" would search for pages that contain the word "password" within the body of the page.

## OUTPUT :

![3 before](https://github.com/user-attachments/assets/15f8e827-d667-4528-9d98-e90539400b1a)



inurl: This operator allows you to search for pages that contain specific text within the URL. For example, "inurl:admin" would search for pages that contain the word "admin" within the URL.

## OUTPUT :
![3](https://github.com/user-attachments/assets/12e2fc04-e5ac-4de3-abdd-21e495904e11)


intitle: This operator allows you to search for pages that contain specific text within the title tag. For example, "intitle:index of" would search for pages that contain "index of" within the title tag.

## OUTPUT :
![4](https://github.com/user-attachments/assets/8cb96acf-067b-4c6e-b273-c004b71fee4f)


link: This operator allows you to search for pages that link to a specific URL. For example, "link:example.com" would search for pages that link to the example.com domain.

## OUTPUT :
![5](https://github.com/user-attachments/assets/8c9e43ab-6111-4794-b4e8-3c402862fbb2)


cache: This operator allows you to view the cached version of a page. For example, "cache:example.com" would show the cached version of the example.com website.
## OUTPUT :
![6 ](https://github.com/user-attachments/assets/6df060bf-b758-4b16-b16e-d7c2fe2ef867)


 
#DNS Enumeration


##DNS Recon
provides the ability to perform:
Check all NS records for zone transfers
Enumerate general DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF , TXT)
Perform common SRV Record Enumeration
Top level domain expansion
## OUTPUT:
![7 1](https://github.com/user-attachments/assets/a45ddabc-f0ce-46fc-9ab6-b7ea198ddb9d)
![8](https://github.com/user-attachments/assets/86bffee8-7e9a-4061-b10b-4871ac96d8a1)


##dnsenum
Dnsenum is a multithreaded perl script to enumerate DNS information of a domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum is to gather as much information as possible about a domain. The program currently performs the following operations:

Get the host’s addresses (A record).
Get the namservers (threaded).
Get the MX record (threaded).
Perform axfr queries on nameservers and get BIND versions(threaded).
Get extra names and subdomains via google scraping (google query = “allinurl: -www site:domain”).
Brute force subdomains from file, can also perform recursion on subdomain that have NS records (all threaded).
Calculate C class domain network ranges and perform whois queries on them (threaded).
Perform reverse lookups on netranges (C class or/and whois netranges) (threaded).
Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts. It also can be used for security tests.

## OUTPUT :

![9](https://github.com/user-attachments/assets/6513a41b-f19c-46f3-a51e-8b3116d1aad4)



## smtp-user-enum
Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN, VRFY or RCPT TO.


In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

select any username in the first column of the above file and check the same


#Telnet for smtp enumeration
Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands
  
 ## Output :
 ![10](https://github.com/user-attachments/assets/0cff5a5a-32b1-4330-ad8f-32926408d10e)


  In metasploit list all the usernames using head /etc/passwd or cat /etc/passwd:

 ## OUTPUT :
![428126899-6181cd5f-f835-48f1-845a-7a45a7c655af](https://github.com/user-attachments/assets/08ed5332-71f1-414c-89c4-aa1d725ee8ba)



 select any username in the first column of the above file and check the same

 ## OUTPUT :
![11](https://github.com/user-attachments/assets/b15f5f8d-ac8b-4287-8ec7-aa3dafc47763)


 ## Telnet for smtp enumeration

Telnet allows to connect to remote host based on the port no. For smtp port no is 25
telnet <host address> 25 to connect
and issue appropriate commands

## OUTPUT :
![12](https://github.com/user-attachments/assets/42f0751d-f42d-4ac0-846d-0afe8dea09bd)


  

## nmap –script smtp-enum-users.nse <hostname>

The smtp-enum-users.nse script attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO commands. The goal of this script is to discover all the user accounts in the remote system.


## OUTPUT:
![13](https://github.com/user-attachments/assets/08b83b49-2500-4929-a04f-4fac5c56bf9d)


## RESULT:
The Google hacking keywords and enumeration tools were identified and executed successfully.

