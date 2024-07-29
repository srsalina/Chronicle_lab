# Investigating a Phishing Email with Chronicle

## Project Description

In this activity, I took on the role of a security analyst for a hypothetical financial services company. An alert notified me that an employee had received a potentially malicious email. Upon investigation, I discovered a suspicious domain within the email's content: <b>signin.office365x24.com</b>. My task was to determine whether this phishing email had targeted other employees and if any of them had interacted with the domain. To proceed with this investigation, I utilized Google Chronicle to trace and analyze the domain's footprint within our network.

### Skills Learned
- Proficiency in using Chroncicle for investigating suspicious domains and IP addresses


## Findings

### Notes on the Suspicious Domain

- I noticed that the suspicious domain was already listed under the <b>DOMAINS</b> section. This indicated that the domain had been previously logged and analyzed. I clicked on the listing to complete my search.

![image](https://github.com/user-attachments/assets/ede467a4-0422-4c8e-b5e7-af22217a23a3)



- I noted a few things upon clicking the listing. I first noticed the domain resolved to two IP addresses: <b>104.215.148.63</b> and <b>40.100.174.34</b>. I also noticed its sibling domain, <b>login.office365x24.com</b>. Finally, I made note of the <b>VT CONTEXT</b> section and the left menu containing the events and assets associated with the suspicious domain. I decided to investigate these further.

![image](https://github.com/user-attachments/assets/bb2de5c0-a576-4dfb-b4c6-e40ab8310ed2)



#### Investigating the VirusTotal Data

- I clicked on <b>VT CONTEXT</b> to view the VirusTotal data. Its score of 10/93 meant that 10 out of the 93 antivirus engines and security tools used by VirusTotal flagged the domain as malicious. This consensus among various security vendors highlighted the domain's potential threat.

![image](https://github.com/user-attachments/assets/0703abcf-7952-40b7-9dd8-8086ef4bb2c5)


#### Investigating the Affected Assets and Events


- I found that several assets accessed the domain. More specifically, six PCs had accessed the suspicious domain on the same date and had presumably been in continuous communication with it for several months. 

![image](https://github.com/user-attachments/assets/d98fd0ca-379e-416a-9d02-adf27deab2df)

- Next, I checked the twenty-four events associated with the domain. There were various <b>GET</b> requests, but the <b>POST</b> data was especially significant, as it suggested that data was sent to the suspicious domain, signifying a potentially successful phish attack. There were five total “POST” requests, and all five came from either emil-palmer-pc or ashton-davidson-pc, two known assets.


![image](https://github.com/user-attachments/assets/96b462f0-892e-484b-9643-23bd9149e2f2)

### Investigating the Resolved IP Addresses
#### Investigating IP Address 104.215.148.63

- The first thing I noticed when clicking on the IP address was the box titled <b>ESET THREAT INTELLIGENCE</b> near the center bottom. Its category was “BlockedOBject” with low confidence. This IP address had a 0/93 VT score.

![image](https://github.com/user-attachments/assets/def20330-71f3-4c2a-a39b-6edba6fc0cd9)

- I found two associated domains in the <b>Domains</b> section. The first listed domain was the original suspicious domain I investigated, <signin.office365x24.com</b>. However, I made a note of a second domain I had not seen before:

![image](https://github.com/user-attachments/assets/f836ca50-29e9-4ef7-9826-e83ded9b9e9e)

Asset and Events Information
- In the assets tab, I found that all six of the previously noted assets had interacted with this IP address, with the addition of two more: <b>amir-david-pc</b> and <b>warren-morris-pc</b>. I noted that of the twenty-two events, five were “POST” requests, meaning that the assets had submitted information to this IP address. Among the assets, only <b>ashton-davidson-pc</b> and <b>warren-morris-pc</b> submitted information to the address.

![image](https://github.com/user-attachments/assets/e9f8765d-c95b-49f4-a5be-99f159a52550)

#### Investigating IP Address 40.100.174.34

- At first glance, I noticed that this IP address had a different ESET threat intelligence report. ESET had blocked the IP address with high confidence that it was malicious. Interestingly enough, however, the IP address had a VT score of 0/93.
- Of the eleven events listed, three “POST” requests were made by three different employees on January 31st, 2023.

![image](https://github.com/user-attachments/assets/c7cd6e79-9b59-4eaf-8c8c-399aa5f0c3af)

- In the <b>DOMAINS</b> tab, I found the domain <b>signin.accounts.gooqle.com</b> again. I decided to investigate this domain after completing my evaluation of this IP address.

![image](https://github.com/user-attachments/assets/925ab4f6-4277-49b3-b3ab-7a68d3922c18)

- I found the same eight assets in the assets tab that I had found when investigating the previous IP address.

![image](https://github.com/user-attachments/assets/ad8c8db6-4d2a-4f91-9600-42c0da69b9ca)

### A Quick Summary of the Second Domain Associated with the Two Resolved Addresses
I quickly scanned the details of the domain <b>signin.accounts-gooqle.com</b>. I noted a few things:
1. There were a total of nine events, of which three were “POST” requests submitted by asset <b>warren-morris-pc</b>.
2. Only two assets interacted with this domain.
3. The VirusTotal score was 0/93, as no security vendors had reported this domain. However, due to its association with the other malicious domain and IP addresses, it was safe to assume it was also malicious.
4. Its two resolved IP addresses were the same ones I had previously investigated.

![image](https://github.com/user-attachments/assets/7863d271-ad27-45a4-bced-a3da453ca963)

### Investigating the Sibling Domain of <b>signin.office365x24.com</b>

- After clicking the domain <b>login.office365x24.com</b>, I observed no associated domains or resolved IP addresses.

![image](https://github.com/user-attachments/assets/228cd4e9-e0bd-40e6-9303-82be3111c2b5)


- This domain was flagged as <b>phishing</b> and <b>malicious</b> by two security vendors.

![image](https://github.com/user-attachments/assets/95ca6f47-8b3e-4548-aadb-8aa00a39c92d)

- Six assets had interacted with this domain. Interestingly enough, the last names of the assets were switched around. I noted this as a potential glitch with the lab environment and moved on. I also found eight events, with two denoted as “POST,” signifying that this domain had also successfully extracted information.

![image](https://github.com/user-attachments/assets/65b91f64-63e1-45eb-98d3-1a481543c46c)

## Conclusion

I found significant evidence suggesting malicious activity after investigating the suspicious domain and its resolved IP addresses. Both IP addresses associated with the domain were accessed by the same eight assets, indicating a pattern of interaction that could signify widespread compromise within the network. The domain was flagged by 10 out of 93 security vendors in VirusTotal, highlighting its potential threat. Its sibling domain also received interaction from the assets and scored a 2/93 VT score. Given these findings, it is reasonable to conclude that the email the employees received was part of a phishing attack orchestrated by a malicious actor.

To mitigate further risks, comprehensive security training for all employees, focusing on recognizing and responding to phishing attacks and email scams, is crucial. Additionally, enhancing network monitoring and implementing stricter email security protocols will help prevent similar incidents in the future.

