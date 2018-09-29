# sysprofiler

Written by khyrenz.com
(https://www.khyrenz.com/contact-us/)

These scripts are provided as-is, with no guarantees whatsoever. Use at your own risk.

Many existing tools are used by the sysprofiler script, including:
* TSK (www.sleuthkit.org)
* RegRipper (https://github.com/keydet89/RegRipper2.8)
* Parse::Win32Registry (http://search.cpan.org/~jmacfarla/Parse-Win32Registry-1.0/lib/Parse/Win32Registry.pm)
* pwdump (https://github.com/moyix/creddump)
* pylnker (https://github.com/HarmJ0y/pylnker)

These tools have their own licenses and their functionality is entirely credited to the relevant authors, who made my script possible.

## sysprofiler-setup

This script installs the relevant packages to allow the sysprofiler script to run.

## sysprofiler-setup-offline

This script installs the packages required to run sysprofiler on an offline system. You will need to download certain tools prior to running this script and when prompted, enter the path to each file to proceed with setup. This script relies on having a local Ubuntu mirror set up to install packages. Instructions for this can be found at khyrenz.com/blog/wsl-for-forensics.

## sysprofiler

A Bash script that uses a number of existing tools to profile a Windows disk image.

During every forensic investigation, no matter whether it's a fraud or malware investigation, there are common artefacts and processes that are always run and added to a typical report. Parsing these artefacts manually can take a significant amount of time that could be better spent interpreting the results or parsing and analysing more complex data. This script therefore automates some of the simpler, more mundane processes, to free up the analyst for more focussed processing and interpretation. It is very much a work in progress and in the early stages of development. However, we are continually developing it to make it useful for us and if you have any feedback or requests for functionality, please do drop us a line on our contact page. Although the script has been tested, this was not exhaustive, so please bear this in mind and feel free to report any issues via our contact page too.

sysprofiler is a Bash script that uses a combination of existing tools and manual processing to extract these artefacts and output them into either a Tab Separated (TSV) file, which can be opened as a spreadsheet, or a plaintext (TXT) file that can be opened in Word Processing software and edited directly into a report. All of the tools used by sysprofiler in the way the script uses them will run natively on Linux. This means that sysprofiler will run on a Linux system, or using WSL on Windows. It is not locked into one specific platform.

### Usage

```
  Usage: sysprofiler_v1.sh -i \<image file to process\> [-f \<output format\>] [-k]
  
  Optional arguments:
  
      -f <output format>  - supported formats: tsv,txt (default is tsv). Only one format at a time is supported.
      -h                  - display this help information
      -k                  - keep files extracted from image file (deleted by default when script completes)
      -m <modules>        - supported modules: osinfo,users,apps,filelist,usbs,networks
                          - (default is all modules).
                             To run multiple modules, separate with commas, eg '-m osinfo,users,usbs'
                             Note: file listing will only be run on the Windows volume
      -n                  - Compare file hashes to NIST NSRL database. Please note, this will take some time!
                             Can be used with modules: apps,filelist
                             Note: If the NIST NSRL database (NSRLFile.txt) does not already exist in /data,
                             it will be downloaded (assuming an Internet connection can be found)
      -p                  - dump out password hashes for users.
      -s                  - include hashes (MD5 and SHA1). Please note, this will take some time!
                             can be used with modules: osinfo,apps,filelist
```

### Modules

#### osinfo
Extract OS information. Includes volume hashes if '-s' option is used. 

                  Fields:
                             Volume Name
                             Volume Serial Number
                             Filesystem
                             Size(bytes)
                             Windows Version
                             Service Pack
                             Owner
                             Organisation
                             Install Date
                             Hostname
                             Timezone
                             Timezone Offset

#### users          
List user accounts on the system. Will also dump user password hashes if '-p' option is used. 

                  Fields:
                             Username
                             SID
                             Full Name
                             Comment
                             Account Created
                             Last Login
                             Login Count
                             Password Set
                             Password Last Reset
                             Last Incorrect Password Entry
                             Password Hint
                             Flags
                             Groups

#### apps          
Lists apps installed on the system for all users (from Installer and Uninstall Registry keys). 

                  Fields:
                             Registry Key
                             User SID
                             Application
                             Version
                             Company
                             Install Date

#### filelist         
Lists all files and folders on the system, including file hashes (MD5 and SHA1) if '-s' option is used and whether present in NIST if '-n' is used.

                   Fields:

                             Volume Serial Number
                             File inode number
                             Type (dir/file)
                             Full Path

#### usbs           
Lists all USB connections on the system, including timestamps in USBSTOR Registry key and extra timestamps extracted from setupapi log.

                   Fields:

                             USB ID
                             Name
                             Serial Number
                             Parent ID Prefix
                             Last Mounted As
                             First Connected
                             Last Connected
                             Last Removed
                             Other Connection Timestamps (from setupapi log)

#### networks    
Lists network connections for system. 

                    Fields:
                             Network Name
                             Type
                             First Connected
                             Last Connected
                             Default Gateway MAC Address