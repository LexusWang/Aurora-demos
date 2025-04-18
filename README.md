[![Release](https://img.shields.io/badge/dynamic/json?color=blue&label=Release&query=tag_name&url=https%5B%5D)](https:%5B%5D)

# Aurora-demos:

This projects contains the attack chains generated by Aurora, a cyberattack emulation system leveraging classical planning (PDDL) and Large Language Models (LLMs).

Aurora is a framework that can automatically construct multi-step cyberattacks (attack chains), set up emulation environments, and semi-automatically execute the generated attack chains. With the help of LLM, it makes use of external attack tools and threat intelligence reports.

We are preparing publishing the source code of Aurora.

## 🎉 Introduction

<p><a href="https://arxiv.org/pdf/2407.16928"><img src="images/First_page.png" alt="Paper thumbnail" align="right" width="160"/></a></p>

-   Introduces AURORA, an cyberattack emulation system leveraging classical planning (PDDL) and Large Language Models (LLMs).
-   Automates construction of a 5,000+ action attack space with over 1,000 chains.
-   AURORA generates higher quality attack plans with broader TTP coverage.

Our paper: [From Sands to Mansions: Towards Automated Cyberattack Emulation with Classical Planning and Large Language Models](https://arxiv.org/pdf/2407.16928)

## Resources & Socials

-   📜 [Documentation, training, and use-cases]()(Coming Soon)
-   ✍️ [aurora's blog]()(Coming Soon)
-   🌐 [Homepage](https://auroraattack.github.io/)

## Attack Demos

This repo stores attack demos generated by Aurora, which can be found in the `examples/` folder. Each folder in `examples/` contains an attach chain, which includes the emulation plan details and attack steps.

### Emulation Plan Details

| Field | Description |
|:--:|----|
| Adversary Name | This refers to the name or codename of the attacker being simulated in the exercise. |
| Creation Time | This indicates the exact date and time when the emulation plan or attack scenario was created. |

### Attack Step

| Field | Description |
|:--:|----|
| uuid | A unique identifier for the attack step, ensuring that each step can be individually referenced and tracked. |
| name | A human-readable name for the attack step, which describes what the step aims to achieve or the action being performed. |
| id | An identifier that may be used within a specific framework or system to reference the attack step. |
| source | The origin or creator of the attack step, which can indicate whether it was developed internally, derived from a known threat intelligence source, or part of a manual process. |
| supported_platforms | The operating systems or environments on which the attack step can be executed. |
| tactics | The high-level goals or phases of the attack that this step supports. |
| technique | The specific methods or technologies used in the attack step. |
| description | A detailed explanation of what the attack step does. |
| executor | The command, script, or series of actions that need to be executed to carry out the attack step. |
| arguments | Any parameters or inputs required by the executor to function correctly. |
| preconditions | The conditions that must be met before the attack step can be successfully executed. |
| effects | The outcomes or changes that result from executing the attack step. |

## Usage

### Pull and deploy the attack range:

After successfully generating the yml file of the attack chain, you can use pull.py to automatically read the files within it to automatically pull and deploy the virtual machine range.

Note that automatic deployment is applicable to VirtualBox. Of course, if you are using Vmware, you can also manually deploy it yourself based on the downloaded files.

There are two modes for download deployment: prohibiting duplicate deployment and allowing duplicate downloads.

When repeated downloading is not allowed, if the storage path has already downloaded a file, it will ask whether it is necessary to start directly.

When repeated downloads are allowed, the downloaded file will be automatically renamed for deployment to prevent conflicts.

Note that during the initial deployment (including the case of duplicate deployment), considering that users may need to modify the configuration, the virtual machine will not start automatically.

Network configuration: The downloaded virtual machine will automatically configure two network cards. One selects the NAT mode and the other selects the Host-only mode. This mode requires users to consider their own configuration for adjustment. If the VirtualBox itself does not configure the corresponding network card, the problem of failure to start will occur.

``` bash
## Prohibiting duplicate deployment
python pull.py -p #yml_file_path -d #storage_path -vm #VBoxManage.exe_path --url_table #url_table_path -nr -firewall #yes/no
## Allowing duplicate downloads
python pull.py -p #yml_file_path -d #storage_path -vm #VBoxManage.exe_path --url_table #url_table_path -r -firewall #yes/no
```
- `yml_file_path`：The path of the attack chain yml file  
- `storage_path`：The storage path of the downloaded target machine file  
- `VBoxManage.exe_path`：The VBoxManage.exe path of VirtualBox is used for invocation  
- `url_table_path`：The path of the Download Link mapping table (url_table.csv)  
- `-nr`：Prohibiting duplicate deployment  
- `-r`：Allowing duplicate downloads  
- `-firewall`：Use pfSense firewall to isolate the attack aircraft and the target aircraft  


Example:If you don't want to allow repeated downloads of the attack chain "examples\access_encrypted_edge_credentials\attack_plan.yml" corresponding to the range. You can use 
``` bash
python pull.py -p examples\access_encrypted_edge_credentials\attack_plan.yml -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table url_table.csv -nr -firewall no
```
If the download folder has already downloaded the corresponding shooting range, it will display:<p align="center">

<img src="images/No_repeat.png" alt="request" width="1200"/>

</p>
Entering "yes" will directly start the corresponding virtual machine of the range.

On the contrary, if repetition is allowed, the downloaded file will be automatically renamed to avoid conflicts.

Besides, if you want to use firewall for isolation. You can use 
``` bash
python pull.py -p examples\access_encrypted_edge_credentials\attack_plan.yml -d download -vm C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe --url_table url_table.csv -nr -firewall yes
```
If it was not downloaded originally, firewall.ova will be automatically downloaded. If there is already a download, it will skip and ask if you want to start it.

When using pfsense, attention should be paid to the configuration. The configuration of the downloaded and deployed pfsense is as follows:
<p align="center">

<img src="images/pfsense.png" alt="pfsense set" width="1200"/>

</p>
Therefore, two corresponding host-only network cards need to be set up in VirtualBox in advance. Meanwhile, it is recommended to turn off the NAT network card.

### The emulation infrastructure

<p align="center">

<img src="images/the%20emulation%20infrastructure.jpg" alt="cli output" width="1200"/>

</p>

Attackers: Kali,Windows 10<br> DNS_server: Debian<br> Firewall: pfSense<br> Victims：Windows 10,macOS,Ubuntu<br>

You can visit this [page](https://auroraattack.github.io) to view more detailed information about executing the attack chain using the simulation environment, or you can directly download the attack simulation environment from [here](https://drive.google.com/file/d/1cx-xcn10rDQaoq1SC9CW__0tbZVA5rEo/view?usp=sharing).

## Generation of attack scripts:

The logic of the script is to configure itself based on the `executor` provided in the `attack_plan.yml`. The script reads `command` and `arguments` by determining the type of `executor` specified. Additionally, it explicitly extracts `arguments` marked as `Required: true` from the `exploit` and `payload` sections of the file and outputs them directly into the executable script. This design simplifies user configuration and minimizes manual intervention. After executing this script, users will obtain a large number of ready-to-run attack scripts, streamlining the setup process and saving operational time

``` bash
python generateExecution.py
```

<p align="center">

<img src="images/generateExecution.gif" alt="editor" align="center"/>

</p>

### Execution of attack script:

``` bash
python ../results/execution_xxxx.py
```

Just configure a few parameters to run the attack script.

Click the following headings for details:

<details>

<summary>EXAMPLE-execution_arp_cache_info_printed-1</summary>

The attack plan demonstrates a multi-stage adversarial strategy targeting `ManageEngine Desktop Central 9` via the `CVE-2015-8249` vulnerability, leveraging `Metasploit` and `ART` frameworks to achieve remote code execution (RCE), establish persistent command and control (C2), and conduct network reconnaissance(arp -a).

![progress](images/example1.gif)

</details>

### Execute the attack manually

Each `uuid` encompasses an `executor`, within which the `command` parameter specifies the actual attack command that needs to be executed. You should proceed manually through the attack steps in the sequence of the UUIDs.

①Download the latest `Sliver` or `Metasploit` for your attack platform, and just run the binary.

``` bash
# Sliver
kali > curl https://sliver.sh/install|sudo bash
kali > sliver 
# Metasploit
kali > sudo apt-get install metasploit-framework
kali > msfconsole 
```

②Utilize `Sliver` or `Metasploit` to generate an implant for the target victim and initiate listening.

③Download the implant manually and execute it on the target machine.

④Interact with a specific session identified by session_id.

⑤Open an interactive shell on the compromised machine.

⑥Execute attack commands, for example, "Copy the Edge browser's default user data directory to a specified location for further analysis."

```         
shell > Copy-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" -Destination "C:\Users\win\Desktop\Edge" -Force -Recurse
```

## System Overview

<p align="center">

<img src="images/framework.png" alt="cli output" width="1000"/>

</p>

## Licensing

To discuss licensing opportunities, please reach out to aurora\@\[\] or directly to [ ](https:).
