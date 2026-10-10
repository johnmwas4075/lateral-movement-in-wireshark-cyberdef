# PsExec Hunt: Investigating Lateral Movement with Wireshark

## Overview

An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicated potential unauthorized access and movement across the network.

The objective of this investigation was to analyze the provided PCAP file using Wireshark to identify the attacker's entry point, determine the compromised and targeted machines, establish the account used for authentication, and identify the network shares and service executable associated with PsExec.

The investigation focused on SMB (Server Message Block) traffic, NTLM authentication messages, file transfers, and communication patterns between hosts.

## 1. Identifying the Attacker's IP Address

I began by examining the overall traffic distribution in the PCAP file to identify the host responsible for generating significant network activity.

First, I reviewed the packet volume and focused on the IP address with the highest traffic volume. I then navigated to **Statistics → Conversations** and selected the IPv4 tab to examine communication between hosts. I looked for the IP address with the highest number of packets and frequent connections.

Next, I filtered the capture to focus on initial SMB negotiation traffic using:

```wireshark
smb.cmd == 0x72 or smb2.cmd == 0x00
```

This helped identify the source IP address initiating SMB connections and establish which host was involved in the suspicious activity.

The three investigation methods pointed to the same IP address.

**Finding:** `10.0.0.130`

<img width="1124" height="602" alt="Screenshot 2026-10-10 144708" src="https://github.com/user-attachments/assets/6d9fc1f8-cd9d-4817-9bce-c0c8c1622823" />


## 2. Identifying the Target Machine's Hostname

To identify the hostname of the machine involved in the initial PsExec activity, I examined NTLMSSP authentication traffic within the capture.

I applied the following Wireshark display filter:

```wireshark
ntlmssp.challenge.target_name
```

This filter highlighted NTLMSSP Challenge messages exchanged during authentication. I inspected the **Target Name** field in the relevant challenge message to determine the hostname of the target machine.

The analysis identified the target machine as:

**Finding:** `SALES-PC`

<img width="1326" height="661" alt="Screenshot 2026-10-10 144546" src="https://github.com/user-attachments/assets/3bbed31b-b48e-49e2-a063-8d1555910e91" />

## 3. Identifying the Authorization Account

Next, I investigated the account used by the attacker to authenticate to the target machine.

PsExec relies on authentication to establish remote access, and the account name can be identified in NTLMSSP Authenticate messages exchanged over SMB.

I applied the following Wireshark filter:

```wireshark
ntlmssp.auth.username
```

I examined the resulting authentication packets and inspected the username field in the NTLMSSP Authenticate message. This revealed the account name submitted during authentication.

**Finding:** `ssales`

<img width="1242" height="614" alt="Screenshot 2026-10-10 144146" src="https://github.com/user-attachments/assets/8bfa653b-6f3b-4530-8f0d-d98bd08aa046" />

## 4. Identifying the Service Executable

PsExec typically installs a service executable on the remote machine to facilitate command execution. Identifying this executable helps establish whether the observed SMB activity is consistent with PsExec-based lateral movement.

To investigate file transfers, I navigated to:

**File → Export Objects → SMB**

This opened the list of objects transferred through SMB in the capture. I reviewed the available filenames to identify the executable associated with the PsExec service installation.

The executable was identified as:

**Finding:** `PSEXESVC.exe`

<img width="1040" height="585" alt="Screenshot 2026-10-10 145212" src="https://github.com/user-attachments/assets/82bea69d-63c9-4d68-a3de-697796f117c8" />

## 5. Identifying the Network Share Used to Install the Service

I then investigated the SMB share used to transfer and install the PsExec service executable on the target machine.

I applied the following Wireshark filter:

```wireshark
smb2.tree
```

I examined the SMB2 tree connection information to identify the network share accessed during the service installation process.

The traffic showed that PsExec used the default Windows administrative share associated with remote access to the system directory. This share is commonly used by administrative tools to copy service executables to remote Windows machines.

**Finding:** `ADMIN$`

<img width="1263" height="673" alt="Screenshot 2026-10-10 145446" src="https://github.com/user-attachments/assets/f5f56b79-d30e-4739-8b0a-abd8db4a4754" />


## 6. Identifying the Network Share Used for PsExec Communication

After identifying the service installation share, I examined the SMB traffic to determine which network share PsExec used for communication between the machines.

PsExec can use named pipes and SMB communication channels to exchange data associated with remote command execution. I reviewed the SMB share activity and looked for indications of standard input, standard output, and standard error streams, including filenames or paths containing `stdin`, `stdout`, or `stderr`.

The investigation identified the share used for this communication as:

**Finding:** `IPC$`

<img width="1254" height="691" alt="Screenshot 2026-10-10 145714" src="https://github.com/user-attachments/assets/481ce46d-8385-429b-815e-7f41c0b5aa2b" />


## 7. Identifying the Second Machine Targeted for Lateral Movement

Finally, I investigated whether the attacker attempted to move laterally to another machine within the network.

I reused the following Wireshark display filter:

```wireshark
ntlmssp.challenge.target_name
```

I examined the NTLMSSP Challenge messages associated with subsequent SMB authentication activity. I checked the **Target Name** and **NetBIOS Computer Name** fields to distinguish the second target from the initially identified machine.

This analysis revealed a second hostname associated with the attacker's lateral movement.

**Finding:** `MARKETING-PC`

<img width="1326" height="661" alt="Screenshot 2026-10-10 144546" src="https://github.com/user-attachments/assets/3bbed31b-b48e-49e2-a063-8d1555910e91" />

## Investigation Findings

| Investigation question              | Finding        |
| ----------------------------------- | -------------- |
| Attacker's IP address               | `10.0.0.130`   |
| Initial target hostname             | `SALES-PC`     |
| Authorization account               | `ssales`       |
| Service executable                  | `PSEXESVC.exe` |
| Share used for service installation | `ADMIN$`       |
| Share used for communication        | `IPC$`         |
| Second machine targeted             | `MARKETING-PC` |

## Attack Reconstruction

The packet capture provided evidence consistent with the following sequence of activity:

```text
Attacker: 10.0.0.130
        |
        v
SMB connection and NTLM authentication
        |
        v
Account: ssales
        |
        v
Initial target: SALES-PC
        |
        v
PSEXESVC.exe transferred using ADMIN$
        |
        v
IPC$ used for PsExec communication
        |
        v
Lateral movement to MARKETING-PC
```

## Conclusion

The Wireshark investigation identified `10.0.0.130` as the suspected attacker IP address and `ssales` as the account used during authentication. The initial target was `SALES-PC`, where `PSEXESVC.exe` was associated with service installation through the `ADMIN$` share. The `IPC$` share was identified as the communication share used by PsExec.

Further analysis of NTLMSSP Challenge messages identified `MARKETING-PC` as the second machine targeted, indicating potential lateral movement within the network.

### These findings demonstrate how packet-level analysis of SMB traffic, NTLMSSP authentication messages, and transferred files can help a SOC analyst investigate suspected PsExec activity and reconstruct an attacker's movement through a network.
