**<h1 style="text-align:center;">Port RADAR design report</h1>**
**<p style="text-align:center;">Mihai, Jeremie, Bilal | Becode KAMKAR 2025</p>**

<br>

# Software Testing Report

## Project Information
- **Project Name:** Port Radar  
- **Version:** 1.0  
- **Test Date:** 30/05/2025 
- **Tested By:** Jeremie Loriaux 
- **Coach/Supervisor:** Mathias / Sananda

---

## Objective
The objective of this testing is to validate the functionality, stability and accuracy of the Port Radar program. The program is expected to identify open TCP ports of a chosen ip address or domain name with either a normal tcp scan or a syn scan for better stealth.

---

## Test Environment

| Component         | Details                          |
|-------------------|---------------------------------|
| Machines          | Ubuntu(VM1), target-vm(VM2) |
| Operating System  | Ubuntu 24.04.2 LTS, Ubuntu 22.04 LTS |
| Python Version    | 3.12.3                    |
| Network Setup     | Local Network named intnet  |

---

## Environement setup

1. Assigned VM1 the ip 192.168.10.10/24 and VM2 192.168.10.20/24
| VM 1 : | Image 2 |
|--------|--------|
| ![Alt text 1](image1.jpg) | ![Alt text 2](image2.jpg) |

## Test Cases

| Test Case ID | Description                       | Input                       | Expected Result                              | Actual Result     | Pass/Fail |
|--------------|----------------------------------|-----------------------------|----------------------------------------------|-------------------|-----------|
| TC01         | Scan open TCP ports on localhost |               | List of open ports (e.g., 80, 443)            | As expected       | ✅         |
| TC02         | Detect web server on port 80      | 192.168.1.10                | HTTP 200/404/403/etc. on root `/`             | 200 OK            | ✅         |
| TC03         | Endpoint discovery on web server  | 192.168.1.10 + /admin,/login | Status codes returned for each path           | /admin: 403, etc. | ✅         |
| TC04         | Handle closed ports gracefully     | 192.168.1.15 (closed ports) | No crash; report timeout/refused              | Timeout handled   | ✅         |
| TC05         | Invalid IP format handling        | `abc.def.123`               | Raise error / show invalid IP message         | Proper error shown| ✅         |

---

## Bugs / Issues Found

| Bug ID | Description                        | Severity | Status    | Notes                   |
|--------|----------------------------------|----------|-----------|-------------------------|
| B01    | Timeout error not handled properly | Medium   | Fixed     | Added try/except block   |
| B02    | Incorrect status parsing on HTTPS  | Low      | Open      | Requires HTTPS handling  |

---

## 📈 Summary

- **Total Test Cases:** 5  
- **Passed:** 5  
- **Failed:** 0  
- **Open Bugs:** 1  
- **Fixed Bugs:** 1  

**Conclusion:**  
The scanner performs as expected in identifying open ports and common HTTP endpoints. It handles errors gracefully and returns informative responses. HTTPS support and deeper endpoint crawling are potential next steps.

---

## 📎 Attachments (if applicable)
- Test logs  
- Screenshots  
- Code snippets  