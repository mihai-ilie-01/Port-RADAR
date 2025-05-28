# Software Design Report

---

## 1. Introduction

### 1.1 Purpose  
Port Radar's purpose is to scan for opened ports on a targetted device.

### 1.2 Scope  
Port Radar at first will only utilise the basic TCP protocol to check if a port is open for an external TCP connection.
In future updates, we plan to implement an option to scan for ports opened to receive UDP packets and a SYN scan option for a stealthier and faster scan.

### 1.3 Definitions, Acronyms, and Abbreviations  
#### 1.3.1 Definitions:
<ins>TCP<ins>>: internet protocol used to reliably transfer data using a three-way handshake(SYN, SYN-ACK, ACK)
<ins>UDP<ins>>: internet protocol that sends out packets without the garentee of arrival or response in contrast with the TCP protocol.
<ins>SYN<ins>>: 
<ins>Port<ins>>:
<ins>Threading<ins>>:

#### 1.3.2 Acronyms:

#### 1.3.3 Abbreviations:

### 1.4 References  
Mention any related documents, specifications, standards, or websites.

---

## 2. Overall Description

### 2.1 Product Perspective  
Describe the product’s relation to other systems (standalone, part of a larger system).  
High-level context and interfaces.

### 2.2 Product Functions  
Summary of the main functionalities provided.

### 2.3 User Characteristics  
Describe the intended users, their experience, and any special requirements.

### 2.4 Constraints  
Hardware, software, regulatory, or design constraints.

### 2.5 Assumptions and Dependencies  
What assumptions are made?  
External dependencies or third-party systems.

---

## 3. Architectural Design

### 3.1 System Architecture Overview  
High-level description of system components and their interactions.  
Include diagrams (e.g., block diagrams, component diagrams).

### 3.2 Design Patterns Used  
List and describe any design patterns applied (MVC, Observer, Singleton, etc.).

### 3.3 Technologies and Tools  
Programming languages, frameworks, libraries, databases, etc.

---

## 4. Detailed Design

### 4.1 Module / Component Description  
For each major module/component:

- **Name**  
- **Purpose**  
- **Responsibilities**  
- **Interfaces**  
- **Inputs and Outputs**  
- **Dependencies**

### 4.2 Data Design  
Description of data models, database schema, file formats, etc.  
Entity-Relationship Diagrams or UML class diagrams.

### 4.3 User Interface Design  
Description or mockups of UI components/screens.

### 4.4 Algorithms and Processing Logic  
Detailed explanation of key algorithms or processing logic.  
Include pseudocode or flowcharts if helpful.

---

## 5. System Integration

### 5.1 External Interfaces  
APIs, protocols, data formats for external system interaction.

### 5.2 Communication  
Communication mechanisms between modules (message queues, REST, RPC, etc.).

---

## 6. Error Handling and Logging

How errors/exceptions are handled at different levels.  
Logging strategy and tools.

---

## 7. Security Considerations

Authentication, authorization, encryption.  
Data protection and privacy.

---

## 8. Performance Considerations

Expected performance metrics.  
Strategies for optimization and scaling.

---

## 9. Testing Strategy

Types of testing planned (unit, integration, system, acceptance).  
Tools and frameworks to be used.  
Test coverage goals.

---

## 10. Deployment

Target environment and platform details.  
Deployment procedures and tools.

---

## 11. Maintenance and Support

Expected maintenance activities.  
How support will be handled.

---

## 12. Appendices

- Glossary  
- Supporting diagrams, additional data  
- Revision history

---

# Example Diagrams to Include

- UML Diagrams: Class, Sequence, Activity  
- Flowcharts for Algorithms  
- Entity-Relationship Diagram for Databases  
- System Architecture Diagram for Components and Connections
