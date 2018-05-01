#!/bin/bash

#Printing help
function print_usage {
	local me=${0##*/}
	echo "=============================="
	echo "Usage:" $me "-i <image file to process> [-f <output format>] [-k]"
	echo "Optional arguments:"
	echo "   -f <output format>    - supported formats: tsv,txt (default is tsv). Only one format at a time is supported."
	echo "   -h                    - display this help information"
	echo "   -k                    - keep files extracted from image file (deleted by default when script completes)"
	echo "   -m <modules>          - supported modules: "$modules
	echo "   -m <modules>          - (default is all modules)."
	echo "                           To run multiple modules, separate with commas, eg '-m osinfo,users,usbs'"
	echo "                           Note: file listing will only be run on the Windows volume"
	echo "   -n                    - Compare file hashes to NIST NSRL database. Please note, this will take some time!"
	echo "                           Can be used with modules: apps,filelist"
	echo "                           Note: If the NIST NSRL database (NSRLFile.txt) does not already exist in /data,"
	echo "                           it will be downloaded (assuming an Internet connection can be found)"
	echo "   -p                    - dump out password hashes for users."
	echo "   -s                    - include hashes (MD5 and SHA1). Please note, this will take some time!"
	echo "                           can be used with modules: osinfo,apps,filelist"
	exit
}

#trim whitespace from start and end of string
function trim_start_end_whitespace {
	#$1 = string to trim
	
	echo $1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//'
}

#convert little-endian string to big-endian
function convert_le_to_be {
	#$1 = Little Endian string to convert_le_to_be
	
	local str_le=$1
	local str_be=${str_le:14:2}${str_le:12:2}${str_le:10:2}${str_le:8:2}${str_le:6:2}${str_le:4:2}${str_le:2:2}${str_le:0:2}
	echo $str_be
}

#convert hex unix epoch date to readable string
function convert_hex_to_readable_unix_date {
	#$1 = unix date in hex
	
	local date_str=$((16#$1))
	date -d @$date_str -Iseconds -u
}

#convert windows filetime hex to unix readable date
function convert_filetime_to_unix_date {
	#$1 = filetime date in hex
	
	if [[ ! -z $1 ]]; then
		local date_str=$(convert_le_to_be $1)
		local date_str=$(echo "ibase=16; ${date_str^^}" | bc)
		local date_str=$(echo $(( (date_str / 10000000) - 11644473600)) )
		date -d @$date_str -Iseconds -u
	else
		echo ""
	fi
}

#convert active bias string to offset string
function convert_bias_to_tz_offset {
	#$1 = active time bias from registry
	
	local offset_str=$((16#$1))
	
	if [[ $offset_str == "ff"* ]]; then
		local hex_ff="ffffffff"
		local hex_ff=$((16#$hex_ff))
		local offset_str=$((((hex_ff-offset_str)+1)/60))
		local offset_str="UTC+"$offset_str
	else
		local offset_str=$((offset_str/60))
		local offset_str="UTC-"$offset_str
	fi
	
	if [[ $offset_str == "UTC"* ]]; then
		echo $offset_str
	else
		echo ""
	fi
}

#Getting volume type for image eg. raw or ewf (e01)
function get_img_type {
	local img_stat_out=$(img_stat $image_file)
	
	for is_line in $img_stat_out; do
		if [[ $is_line == "Image Type:"* ]]; then
			local type=$(echo $is_line | sed 's/Image Type://' | tr -d '[:space:]')
		fi
	done
	
	if [[ -z $type ]]; then
		print_usage
		exit
	fi
	
	echo $type
}

#getting filesystem type
function get_fs_type {	
	local fsstat_out=$(fsstat -i $img_type -o $start_sec $image_file 2>/dev/null)
	
	if [[ ! -z $fsstat_out ]]; then
		for fs_line in $fsstat_out; do
			if [[ $fs_line == "File System Type:"* ]]; then
				echo $fs_line | sed 's/File System Type://' | tr -d '[:space:]'
				break
			fi
		done
	fi
}

#getting volume serial number
function get_vol_sn {	
	local fsstat_out=$(fsstat -i $img_type -o $start_sec $image_file 2>/dev/null)
	
	if [[ ! -z $fsstat_out ]]; then
		for fs_line in $fsstat_out; do
			if [[ $fs_line == "Volume Serial Number:"* ]]; then
				echo $fs_line | sed 's/Volume Serial Number://' | tr -d '[:space:]'
				break
			fi
		done
	fi
}

#checking for Windows volume
function is_windows_volume {	
	if [[ $img_method == "physical" ]]; then
		if [[ -z $fs_type ]]; then
			local fls_out=$(fls -i $img_type -D -o $start_sec $image_file | grep Windows)
		else
			local fls_out=$(fls -i $img_type -f $fs_type -D -o $start_sec $image_file | grep Windows)
		fi
		
		if [[ -z $fls_out ]]; then
			echo false
		else
			echo true
		fi
	else
		echo true
	fi
}

#extracting file from image
function extract_file {
	#$1 = path of file to extract
	
	local filename=$(basename $1)
	if [[ -z $fs_type ]]; then
		local fls_out=$(fls -i $img_type -r -p -F -u -o $start_sec $image_file | grep -i $1)
	else
		local fls_out=$(fls -i $img_type -f $fs_type -r -p -F -u -o $start_sec $image_file | grep -i $1)
	fi
	
	for fls_line in $fls_out; do
		if [[ "${fls_line,,}" == *$'\t'"${1,,}" ]]; then
			#exact match to desired file
			local inode=$(echo $fls_line | cut -d':' -f1 | cut -d' ' -f2)
			icat -i $img_type -f $fs_type -s -o $start_sec $image_file $inode > $dumppath/$filename
		fi
	done
}

#Getting volume information for physical image
function get_volume_info_from_mmls {
	#$1 = mmls output line
	
	local vol_no=$(echo $1 | cut -d':' -f1)
	local size=$(echo $1 | sed 's/ \+/ /g' | cut -d' ' -f5)
	
	#building output string with parsed values
	local out_str=$(get_volume_info $size)
	
	#calculating hashes if option selected
	if [[ ( "$hash" == true ) ]]; then
		echo "Hashing volume at offset "$start_sec"..." > /dev/tty
		local hashes=$(mmcat -i $img_type $image_file $vol_no 2>/dev/null | ((tee /dev/fd/5 | md5sum >/dev/fd/4) 5>&1 | sha1sum) 4>&1)
		local md5=$(echo $hashes | cut -d'-' -f1 | tr -d '[:space:]' | sed 's/\-$//')
		local sha1=$(echo $hashes | cut -d'-' -f2 | tr -d '[:space:]' | sed 's/\-$//')
		local out_str=$out_str"|"$md5"|"$sha1
	fi
	
	echo $out_str
}

function get_volume_info {	
	#$1 = volume size
	
	local vol_name=""
	
	#getting filesystem info using fsstat and parsing
	local fsstat_out=$(fsstat -i $img_type -o $start_sec $image_file 2>/dev/null)
	
	if [[ ! -z $fsstat_out ]]; then
		for fs_line in $fsstat_out; do
			if [[ $fs_line == "Volume Name:"* ]]; then
				local vol_name=$(echo $fs_line | sed 's/Volume Name://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
		done
	fi
	
	#building output string with parsed values
	local out_str=$vol_name"|"$vol_sn"|"$fs_type
	
	#if input image is a logical image, extract size
	if [[ ( $img_method == "logical" ) ]]; then
		local img_stat_out=$(img_stat $image_file)
		
		#extracting size from img_stat output for volume
		local size=""
		for is_line in $img_stat_out; do
			if [[ $is_line == "Size of data in bytes:"* ]]; then
				local size=$(echo $is_line | sed 's/Size of data in bytes://' | tr -d '[:space:]')
			fi
		done
		local out_str=$out_str"|"$size
	else
		local out_str=$out_str"|"$1
	fi
	
	#extracting additional info using regripper for windows volume
	if [[ "$(is_windows_volume)" == true ]]; then
		local winver=$(rip -p winnt_cv -r $dumppath"/SOFTWARE")
		for cv_line in $winver; do
			#stripping leading whitespace
			cv_line=$(echo $cv_line | sed -e 's/^[[:space:]]*//')
			
			if [[ $cv_line == "ProductName :"* ]]; then
				local win_ver=$(echo $cv_line | sed 's/ProductName ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $cv_line =~ "CSDVersion :"* ]]; then
				local serv_pack=$(echo $cv_line | sed 's/CSDVersion ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $cv_line =~ "RegisteredOwner :"* ]]; then
				local owner=$(echo $cv_line | sed 's/RegisteredOwner ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $cv_line =~ "RegisteredOrganization :"* ]]; then
				local company=$(echo $cv_line | sed 's/RegisteredOrganization ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $cv_line =~ "InstallDate :"* ]]; then
				local install_date=$(echo $cv_line | sed 's/InstallDate ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
		done
		
		local compname=$(rip -p compname -r $dumppath"/SYSTEM")
		for cp_line in $compname; do
			#stripping leading whitespace
			cp_line=$(echo $cp_line | sed -e 's/^[[:space:]]*//')
			
			if [[ $cp_line == "ComputerName"* ]]; then
				local comp_name=$(echo $cp_line | sed 's/ComputerName    =//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
		done
		
		local tzinfo=$(rip -p timezone -r $dumppath"/SYSTEM")
		for tz_line in $tzinfo; do
			#stripping leading whitespace
			tz_line=$(echo $tz_line | sed -e 's/^[[:space:]]*//')
			
			if [[ $tz_line == "StandardName"* ]]; then
				local tz_name=$(echo $tz_line | sed 's/StandardName   ->//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $tz_line == "TimeZoneKeyName"* ]]; then
				local tzkn_name=$(echo $tz_line | sed 's/TimeZoneKeyName->//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $tz_line == "ActiveTimeBias"* ]]; then
				local tz_bias=$(echo $tz_line | sed 's/ActiveTimeBias ->//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//' | cut -d '(' -f2 | cut -d ')' -f1)
				if [[ $tz_bias == "0"* ]]; then
					local tz_bias="UTC-"$tz_bias
				else
					local tz_bias="UTC"$tz_bias
				fi
			fi
		done
	fi
	
	if [[ $tz_name == "@"* ]]; then
		local out_str=$out_str"|"$win_ver"|"$serv_pack"|"$owner"|"$company"|"$install_date"|"$comp_name"|"$tzkn_name"|"$tz_bias
	else
		local out_str=$out_str"|"$win_ver"|"$serv_pack"|"$owner"|"$company"|"$install_date"|"$comp_name"|"$tz_name"|"$tz_bias
	fi
	
	#if input image is a logical image, extract hashes (optional)
	if [[ ( $img_method == "logical" ) ]]; then
		#calculating hashes if option selected
		if [[ ( "$hash" == true ) ]]; then
			echo "Hashing volume..." > /dev/tty
			local hashes=$(img_cat -i $img_type $image_file | ((tee /dev/fd/5 | md5sum >/dev/fd/4) 5>&1 | sha1sum) 4>&1)
			local md5=$(echo $hashes | cut -d'-' -f1 | tr -d '[:space:]' | sed 's/\-$//')
			local sha1=$(echo $hashes | cut -d'-' -f2 | tr -d '[:space:]' | sed 's/\-$//')
			local out_str=$out_str"|"$md5"|"$sha1
		fi
	fi
	
	echo $out_str
}

#get list of users
function get_user_info {
	#extracting user info using regripper for windows volume
	if [[ "$(is_windows_volume)" == true ]]; then
		local userinfo=$(rip -p samparse -r $dumppath"/SAM")
		local flags=""
		local user_count=0
		local grp_count=0
		
		for us_line in $userinfo; do
			#stripping leading whitespace
			us_line=$(echo $us_line | sed -e 's/^[[:space:]]*//')
			
			#parsing user info
			if [[ $us_line == "Username"* ]]; then
				#add previous user info to array
				if [[ $user_count -gt 0 ]]; then
					local users[$user_count-1]=$(echo $username"|"$short_sid"|"$fullname"|"$comment"|"$created_date"|"$last_login_date"|"$login_count"|"$pwd_set"|"$pwd_reset_date"|"$pwd_fail_date"|"$pwd_hint"|"$flags"|")
					
					#resetting values to prevent crossover
					local username=""
					local short_sid=""
					local fullname=""
					local comment=""
					local created_date=""
					local last_login_date=""
					local pwd_set=""
					local pwd_reset_date=""
					local pwd_fail_date=""
					local pwd_hint=""
					local login_count=""
					local flags=""
					local newflag=""
				fi
				
				local username=$(echo $us_line | sed 's/Username        ://' | cut -d '[' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				local short_sid=$(echo $us_line | sed 's/Username        ://' | cut -d '[' -f2 | cut -d ']' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				(( user_count++ ))
				
				#using RID (short SID) to parse 'V' key to get flag for set password
				local hex_rid=$(echo "obase=16; $short_sid" | bc )
				local hex_rid=$(printf "%08x" 0x$hex_rid)
				local hex_rid=${hex_rid^^}
				local user_keys=$(get_reg_value $dumppath/SAM SAM\\Domains\\Account\\Users\\$hex_rid)
				for ukey in $user_keys; do
					if [[ $ukey == "V (REG_BINARY) ="* ]]; then
						local v_key=$(echo $ukey | sed 's/V (REG_BINARY) =//' | sed -e 's/[[:space:]]//g')
						local pass_set_flag=${v_key:344:2}
						if  [[ $pass_set_flag == "14" ]]; then
							local pwd_set=true
						else
							local pwd_set=false
						fi
					fi
				done
			fi
			if [[ $us_line == "Full Name"* ]]; then
				local fullname=$(echo $us_line | sed 's/Full Name       ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "User Comment"* ]]; then
				local comment=$(echo $us_line | sed 's/User Comment    ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Account Created"* ]]; then
				local created_date=$(echo $us_line | sed 's/Account Created ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Last Login Date"* ]]; then
				local last_login_date=$(echo $us_line | sed 's/Last Login Date ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Pwd Reset Date"* ]]; then
				local pwd_reset_date=$(echo $us_line | sed 's/Pwd Reset Date  ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Pwd Fail Date"* ]]; then
				local pwd_fail_date=$(echo $us_line | sed 's/Pwd Fail Date   ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Password Hint"* ]]; then
				local pwd_hint=$(echo $us_line | sed 's/Password Hint   ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "Login Count"* ]]; then
				local login_count=$(echo $us_line | sed 's/Login Count     ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $us_line == "-->"* ]]; then
				if [[ -z $flags ]]; then
					local flags=$(echo $us_line | sed 's/-->//' | sed -e 's/^-*//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				else
					local newflag=$(echo $us_line | sed 's/-->//' | sed -e 's/^-*//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
					if [[ -z flags ]]; then
						local flags=$newflag
					else
						if [[ ! -z $newflag ]]; then
							local flags=$flags";"$newflag
						fi
					fi
				fi
			fi
			
			#parsing group info
			if [[ $us_line == "Group Name"* ]]; then
				if [[ $grp_count -eq 0 ]]; then
					#add last user to user info array
					local users[$user_count-1]=$(echo $username"|"$short_sid"|"$fullname"|"$comment"|"$created_date"|"$last_login_date"|"$login_count"|"$pwd_set"|"$pwd_reset_date"|"$pwd_fail_date"|"$pwd_hint"|"$flags"|")
				fi
				
				local groupname=$(echo $us_line | sed 's/Group Name    ://' | cut -d '[' -f1 | tr -d '\n' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				(( grp_count++ ))
			fi
			if [[ $us_line == "S-1-5-"* ]]; then
				local grp_user_sid=$(trim_start_end_whitespace $us_line)
				for uindex in ${!users[@]}; do	
					local user_sid=$(echo "${users[$uindex]}" | cut -d '|' -f2)
					local user=$(echo "${users[$uindex]}")
					
					#checking if SID is full SID or short SID
					if [[ ${#user_sid} -gt 5 ]]; then
						#full SID
						if [[ $grp_user_sid == $user_sid ]]; then
							#adding group name to end of user string
							if [[ $user == *"|" ]]; then
								local users[$uindex]=$(echo "${users[$uindex]}"$groupname)
							else
								local exist_grps=$(echo "${user##*|}")
								if [[ $exist_grps != *$groupname* ]]; then
									local users[$uindex]=$(echo "${users[$uindex]}"";"$groupname)
								fi
							fi
						fi
					else		
						#short SID
						if [[ $grp_user_sid == *$user_sid ]]; then
							#adding group name to end of user string & updating short SID to long SID
							if [[ $user == *"|" ]]; then			
								local users[$uindex]=$(echo "${users[$uindex]}"$groupname | sed "s/|$user_sid|/|$grp_user_sid|/")
							else
								local exist_grps=$(echo "${user##*|}")
								if [[ $exist_grps != *$groupname* ]]; then
									local users[$uindex]=$(echo "${users[$uindex]}"";"$groupname | sed "s/|$user_sid|/|$grp_user_sid|/")
								fi
							fi
						fi
					fi
				done
			fi
		done
	fi
	
	#printing user array to output file
	for user in "${users[@]}"; do
		write_out $user $out_file_users $out_file_users_header
	done
}

#getting a list of all files and folders in the volume
function get_file_list {
	if [[ -z $fs_type ]]; then
		local fls_out=$(fls -i $img_type -o $start_sec -pr $image_file)
	else
		local fls_out=$(fls -i $img_type -f $fs_type -o $start_sec -pr $image_file)
	fi
	
	for fls_line in $fls_out; do
		#determining whether item is file or directory
		local file_type=$(echo $fls_line | cut -d ' ' -f1)
		if [[ $file_type == *"d"* ]]; then
			local file_type="directory"
		else
			local file_type="file"
		fi
		
		#getting file inode and path
		local file_inode=$(echo $fls_line | cut -d ':' -f1 | cut -d '*' -f2 | cut -d ' ' -f2)
		local file_path=$(echo $fls_line | cut -d ':' -f2 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
		
		local out_str=$vol_sn"|"$file_inode"|"$file_type"|"$file_path
		
		#calculating hashes if option selected
		if [[ ( "$hash" == true ) && ( $file_type == "file" ) ]]; then
			echo "Hashing file" $file_path"..." > /dev/tty
			local hashes=$(icat -i $img_type -f $fs_type -s -o $start_sec $image_file $file_inode 2>/dev/null | ((tee /dev/fd/5 | md5sum >/dev/fd/4) 5>&1 | sha1sum) 4>&1)
			local md5=$(echo $hashes | cut -d'-' -f1 | tr -d '[:space:]' | sed 's/\-$//')
			local sha1=$(echo $hashes | cut -d'-' -f2 | tr -d '[:space:]' | sed 's/\-$//')
			local out_str=$out_str"|"$md5"|"$sha1
			
			#checking against NIST NSRL database if option selected
			if [[ ( "$nist" == true ) ]]; then
				#downloading database if doesn't already exist
				if [[ ! -f "/data/NSRLFile.txt" ]]; then
					#downloading latest NIST NSRL hashes (minimal)
					wget -q https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
					unzip -q rds_modernm.zip
					cp NSRLFile.txt /data
					#cleaning up
					rm NSRL*
					rm rds_modernm.zip
				fi
				
				local spec_index=0
				local nist_match=false
				local nist_type=""
				
				TIFS=$IFS
				IFS=","
				for i in $(head -n 1 /data/NSRLFile.txt); do
					if [[ "$i" != "\"SpecialCode\"" ]]; then
						(( spec_index++ ))
					else
						break
					fi
				done
				IFS=$TIFS
				
				local nist_out=$(grep -i -m 1 $sha1 /data/NSRLFile.txt | cut -d ',' -f$spec_index)
				if [[ ! -z $nist_out ]]; then
					#file listed in NIST NSRL database
					local nist_match=true
					local nist_out=$(echo $nist_out | sed 's/"//g' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
					if [[ -z $nist_out ]]; then
						local nist_type="KNOWN"
					fi
					if [[ $nist_out == "M" ]]; then
						local nist_type="MALICIOUS"
					fi
					if [[ $nist_out == "S" ]]; then
						local nist_type="SPECIAL"
					fi
				else
					local nist_match=false
					local nist_type=""
				fi
				
				local out_str=$out_str"|"$nist_match"|"$nist_type
			fi
		fi
		
		#writing to output file
		write_out $out_str $out_file_filelist ""
	done
}

#getting USB information
function get_usb_info {
	#extracting USB info using regripper for windows volume
	if [[ "$(is_windows_volume)" == true ]]; then
		local usbinfo=$(rip -p usbstor -r $dumppath"/SYSTEM")
		
		local usb_id_str=""
		local usb_name=""
		local usb_sn=""
		local usb_parent_id_prefix=""
		local mountdrive=""
		
		#getting currentcontrolset - required to extract timestamps directly from registry
		local selectkey=$(get_reg_value TEMP/SYSTEM Select)
		for selkey in $selectkey; do
			if [[ $selkey == "Current"* ]]; then
				local currcontrolset=$(echo $selkey | sed 's@.*(@@' | sed 's/)//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				local currcontrolset="ControlSet00"$currcontrolset
			fi
		done
		
		for usb_line in $usbinfo; do
			if [[ ( $usb_line == "Disk&Ven"* ) || ( $usb_line == "Other&Ven"* ) ]]; then
				if [[ ! -z $usb_id_str ]]; then
					#getting extra timestamps from registry that are not included in regripper (if currentcontrolset is known)
					if [[ ! -z $currcontrolset ]]; then
						local firstinstall=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064)
						local firstinstall=$(echo $firstinstall | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
						local firstinstall=$(convert_filetime_to_unix_date $firstinstall)
						
						local lastconnect=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066)
						local lastconnect=$(echo $lastconnect | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
						local lastconnect=$(convert_filetime_to_unix_date $lastconnect)
						
						local lastremoved=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067)
						local lastremoved=$(echo $lastremoved | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
						local lastremoved=$(convert_filetime_to_unix_date $lastremoved)
					fi
					
					#getting extra timestamps from setupapi, if applicable
					if [[ -f $dumppath/setupapi.dev.log ]]; then
						local grep_res=$(grep -ai -A1 "Device Install (Hardware initiated) - [A-Za-z0-9?&_#\\\\]*USBSTOR[A-Za-z0-9?&_#\\\\]*"$usb_sn $dumppath"/setupapi.dev.log")
						local setupapi_times=""
						for grep_line in $grep_res; do
							if [[ $grep_line == *"Section start"* ]]; then
								if [[ -z $setupapi_times ]]; then
									local setupapi_times=$(echo $grep_line | sed -e 's/^>*//' | sed 's/Section start//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
									local setupapi_times=$(date -d $setupapi_times -Iseconds -u)
								else
									local new_time=$(echo $grep_line | sed -e 's/^>*//' | sed 's/Section start//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
									local new_time=$(date -d $new_time -Iseconds -u)
									local setupapi_times=$setupapi_times";"$new_time
								fi
							fi
						done
					fi
					
					#write out existing info before moving onto next section
					local out_str=$usb_id_str"|"$usb_name"|"$usb_sn"|"$usb_parent_id_prefix"|"$mountdrive"|"$firstinstall"|"$lastconnect"|"$lastremoved"|"$setupapi_times
					write_out $out_str $out_file_usbs $out_file_usbs_header
					
					#resetting variables to prevent crossover
					local usb_id_str=""
					local usb_name=""
					local usb_sn=""
					local usb_parent_id_prefix=""
					local mountdrive=""
					local firstinstall=""
					local lastconnect=""						
					local lastremoved=""
					local setupapi_times=""
				fi
				
				local usb_id_str=$(echo $usb_line | cut -d '[' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $usb_line == *"S/N"* ]]; then
				local usb_sn=$(echo $usb_line | sed -e 's/^[[:space:]]*//' | sed 's/S\/N://' | cut -d '[' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $usb_line == *"FriendlyName"* ]]; then
				local usb_name=$(echo $usb_line | sed -e 's/^[[:space:]]*//' | sed 's/FriendlyName    ://' | cut -d '[' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			fi
			if [[ $usb_line == *"ParentIdPrefix"* ]]; then
				local usb_parent_id_prefix=$(echo $usb_line | sed -e 's/^[[:space:]]*//' | sed 's/ParentIdPrefix://' | cut -d '[' -f1 | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
				
				local md_info=$(echo $mountinfo | grep -a3 "$usb_parent_id_prefix""&RM")
				local md_info=$(rip -p mountdev -r $dumppath"/SYSTEM" | grep -a2 "$usb_parent_id_prefix""&RM")
				
				if [[ ! -z $md_info ]]; then
					for md_line in $md_info; do
						if [[ $md_line == *"\\DosDevices\\"* ]]; then
							local mountdrive=$(echo $md_line | sed -e 's/^[[:space:]]*//' | sed 's/\\DosDevices\\//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
						fi
					done
				fi
			fi
		done
		
		#getting extra timestamps from registry for last USB (if currentcontrolset is known)
		if [[ ! -z $currcontrolset ]]; then
			local firstinstall=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0064)
			local firstinstall=$(echo $firstinstall | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
			local firstinstall=$(convert_filetime_to_unix_date $firstinstall)
			
			local lastconnect=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0066)
			local lastconnect=$(echo $lastconnect | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
			local lastconnect=$(convert_filetime_to_unix_date $lastconnect)
			
			local lastremoved=$(get_reg_value $dumppath/SYSTEM $currcontrolset\\Enum\\USBSTOR\\$usb_id_str\\$usb_sn\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0067)
			local lastremoved=$(echo $lastremoved | cut -d '=' -f2 | sed -e 's/[[:space:]]//g')
			local lastremoved=$(convert_filetime_to_unix_date $lastremoved)
		fi
					
		#getting extra timestamps from setupapi for last USB, if applicable
		if [[ -f $dumppath/setupapi.dev.log ]]; then
			local grep_res=$(grep -ai -A1 "Device Install (Hardware initiated) - [A-Za-z0-9?&_#\\\\]*USBSTOR[A-Za-z0-9?&_#\\\\]*"$usb_sn $dumppath"/setupapi.dev.log")
			local setupapi_times=""
			
			for grep_line in $grep_res; do
				if [[ $grep_line == *"Section start"* ]]; then
					if [[ -z $setupapi_times ]]; then
						local setupapi_times=$(echo $grep_line | sed -e 's/^>*//' | sed 's/Section start//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
						local setupapi_times=$(date -d $setupapi_times -Iseconds -u)
					else
						local new_time=$(echo $grep_line | sed -e 's/^>*//' | sed 's/Section start//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
						local new_time=$(date -d $new_time -Iseconds -u)
						local setupapi_times=$setupapi_times";"$new_time
					fi
				fi
			done
		fi
					
		#write out info for last USB listed
		local out_str=$usb_id_str"|"$usb_name"|"$usb_sn"|"$usb_parent_id_prefix"|"$mountdrive"|"$firstinstall"|"$lastconnect"|"$lastremoved"|"$setupapi_times
		write_out $out_str $out_file_usbs $out_file_usbs_header
	fi
}

#getting info for installed applications
function get_apps {
	#getting installed app info using RegRipper
	local installer_info=$(rip -p installer -r $dumppath"/SOFTWARE")
	local next=false
	local app_count=0
	
	#parsing output & extracting fields of interest
	for inst_line in $installer_info; do
		if [[ $next == true ]]; then
			local reg_key=$inst_line
			local next=false
		fi
		if [[ $inst_line == "Installer" ]]; then
			local next=true
		fi
		if [[ $inst_line == "User SID"* ]]; then
			local user_sid=$(echo $inst_line | sed 's/User SID://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
		fi
		
		if [[ $inst_line =~ [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]" -"* ]]; then
			local install_date="${inst_line%%-*}"
			local app_name=$(echo $inst_line | sed 's/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9] - //' | sed "s/([^(]*$//" | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			local app_ver="${app_name##* }"
			local app_name="${app_name% *}"
			local app_mfr=$(echo $inst_line | sed 's@.*(@@' | sed 's/)//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			
			#adding info to array
			local apps[$app_count]=$reg_key"|"$user_sid"|"$app_name"|"$app_ver"|"$app_mfr"|"$install_date
			(( app_count++ ))
			
			#resetting variables to prevent crossover
			local app_name=""
			local app_ver=""
			local app_mfr=""
			local install_date=""
		fi
	done
	
	#getting uninstallation app info using RegRipper
	local uninstall_info=$(rip -p uninstall_tln -r $dumppath"/SOFTWARE")
	local next=false
	local user_sid=""
	local app_mfr=""
	
	#parsing output & extracting fields, then comparing to info already in array - adding new apps
	for uninst_line in $uninstall_info; do
		if [[ $next == true ]]; then
			local reg_key=$uninst_line
			local next=false
		fi
		if [[ $uninst_line == "Uninstall" ]]; then
			local next=true
		fi
		if [[ $uninst_line =~ [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"|"* ]]; then
			#Line format is <date>|REG|||[Uninstall] - <app> <version>
			#eg. 1088589366|REG|||[Uninstall] - OutlookFolders 2.0.12
			local app_name=${uninst_line#*\[Uninstall\] - }
			local app_ver=$(echo "${app_name##* }" | sed 's/^v\.//' | sed 's/^v//' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			
			#checking parsing was right & version is a number, otherwise change back
			if [[ $app_ver =~ ^[0-9] ]]; then
				local app_name=$(echo "${app_name% *}" | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			else
				local app_ver=""
			fi
			
			#checking if app is already in array & if not, adding it
			local found=$(array_contains $app_name "${apps[@]}")
			if [[ "$found" == false ]]; then
				#extracting date
				local install_date="${uninst_line%%|*}"
				local install_date=$(date -d @$install_date -Iseconds -u)
				
				#add to array
				local apps[$app_count]=$reg_key"|"$user_sid"|"$app_name"|"$app_ver"|"$app_mfr"|"$install_date
				(( app_count++ ))
			fi
		fi
	done
	
	#writing app info out
	for inst_app in "${apps[@]}"; do
		write_out $inst_app $out_file_apps_all $out_file_apps_header
	done
}

function array_contains {
    local search_for=$1; shift
    local found=false
	
    for arr_elem; do
        if [[ $arr_elem == *$search_for* ]]; then
            local found=true
            break
        fi
    done
	
    echo $found
}

#getting info for installed applications
function get_network_info {
	#getting network info using RegRipper
	local network_info=$(rip -p networklist -r $dumppath"/SOFTWARE")
	local net_count=0
	
	for net_line in $network_info; do
		if [[ $net_line == "Date"* ]]; then
			break
		fi
		if [[ ( $net_line != " "* ) && ( $net_line != "Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"* ) && ( $net_line != "Launching networklist"* ) && ( $net_line != "(Software)"* ) ]]; then
			if [[ $net_count -gt 0 ]]; then
				#write line out to file
				local out_str=$net_name"|"$net_type"|"$net_first_connect"|"$net_last_connect"|"$net_mac
				write_out $out_str $out_file_networks $out_file_networks_header
				
				#resetting variables to prevent crossover
				local net_name=""
				local net_last_connect=""
				local net_first_connect=""
				local net_mac=""
				local net_type=""
			fi
			
			local net_name=$(echo $net_line | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			(( net_count++ ))
		fi
		if [[ $net_line == *"DateLastConnected"* ]]; then
			local net_last_connect=$(echo $net_line | sed 's/DateLastConnected://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			local net_last_connect=$(date -d $net_last_connect -Iseconds -u)
		fi
		if [[ $net_line == *"DateCreated"* ]]; then
			local net_first_connect=$(echo $net_line | sed 's/DateCreated      ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
			local net_first_connect=$(date -d $net_first_connect -Iseconds -u)
		fi
		if [[ $net_line == *"DefaultGatewayMac"* ]]; then
			local net_mac=$(echo $net_line | sed 's/DefaultGatewayMac://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
		fi
		if [[ $net_line == *"Type"* ]]; then
			local net_type=$(echo $net_line | sed 's/Type             ://' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
		fi
	done
	
	#write last line out to file
	local out_str=$net_name"|"$net_type"|"$net_first_connect"|"$net_last_connect"|"$net_mac
	write_out $out_str $out_file_networks $out_file_networks_header
}

#extracting registry value for key
function get_reg_value {
	#$1 = registry hive file
	#$2 = registry key to export
	#$3 = (optional) grep value
	
	#example: hivexregedit --export --prefix 'HKEY_LOCAL_MACHINE\SYSTEM' SYSTEM '\Select'
	#hivexregedit --export --prefix $2 $1 '\'$3 2>/dev/null
	
	#example: regdump.pl TEMP/SAM SAM\\Domains\\Account\\Users -rv | grep UserPasswordHint
	if [[ -z $3 ]]; then
		regdump.pl $1 $2 -rv 2>/dev/null
	else
		regdump.pl $1 $2 -rv 2>/dev/null | grep -i $3 
	fi
}

function parse_lnk {
	#$1 = LNK file path (inc. name)
	
	local lnk_info=$(pylnker.py $1)
	
	for lnk_line in $lnk_info; do
		echo $lnk_line
	done
}

#writing output to file
function write_out {
	#$1 = pipe-separated string to write out
	#$2 = output file
	#$3 = pipe-separated output file header (to convert to key-value pairs)
		
	if [[ $out_format == "tsv" ]]; then
		local out_line=$(echo $1 | sed 's/|/\t/g')
		echo -e $out_line >> $2
	fi
	if [[ $out_format == "txt" && $1 != $3 ]]; then
		#checking if data to print is a single value, or key-value pair(s)
		local empty_str_check=$(echo $1 | sed 's/|//g')
		if [[ -z $empty_str_check ]]; then
			echo "None" >> "$2"
		elif [[ -z $3 ]]; then
			echo $1 >> "$2"
		else
			#getting number of pipes in string & adding one to get number of fields
			local max=$(echo "${1}" | awk -F"|" '{print NF-1}')
			(( max++ ))
			local count=1
			
			#printing out key-value pairs
			while [ $count -le $max ]; do
				local key=$(echo $3 | cut -d '|' -f$count)
				local value=$(echo $1 | cut -d '|' -f$count)
				echo $key": "$value >> "$2"
				(( count++ ))
			done
		fi
		
		#printing newline
		echo "" >> "$2"
	fi
}

function delete_existing {
	#$1 = filename
	
	if [[ -f $1 ]]; then
		rm $1
	fi
}

#-------------------- MAIN function -------------------
#Checking command is valid
image_file=""
out_format="tsv"
out_file_prefix="report"
modules="osinfo,users,apps,filelist,usbs,networks"
dumppath="TEMP"
help=false
keep=false
hash=false
nist=false
passdump=false
img_method=""
next=0

#getting input parameters
for var in "$@"; do
	if [[ next -eq 1 ]]; then
		image_file=$var
		next=0
	fi
	if [[ next -eq 2 ]]; then
		out_format=$var
		next=0
	fi
	if [[ next -eq 3 ]]; then
		modules=$var
		next=0
	fi
	
	if [[ $var == "-i" ]]; then
		next=1
	fi
	if [[ $var == "-f" ]]; then
		next=2
	fi
	if [[ $var == "-m" ]]; then
		next=3
	fi
	if [[ $var == "-h" ]]; then
		help=true
	fi
	if [[ $var == "-k" ]]; then
		keep=true
	fi
	if [[ $var == "-n" ]]; then
		nist=true
	fi
	if [[ $var == "-p" ]]; then
		passdump=true
	fi
	if [[ $var == "-s" ]]; then
		hash=true
	fi
done

#printing help if input file is not provided or output format is specified and an unsupported type
if [[ ( -z "$image_file" ) || ( $out_format != "tsv" && $out_format != "txt") || ( "$help" == true ) ]]; then
	print_usage
fi

#printing error if input file does not exist
if [[ ! -f "$image_file" ]]; then
	echo "ERROR: Image file does not exist"
	echo ""
	print_usage
fi

#setting field separator to newline
OLDIFS=$IFS
IFS=$'\n'

#checking proposed output files do not already exist & deleting if applicable
if [[ $out_format == "tsv" ]]; then
	out_file_os=$out_file_prefix"_osinfo."$out_format
	out_file_users=$out_file_prefix"_userinfo."$out_format
	out_file_filelist=$out_file_prefix"_filelist."$out_format
	out_file_usbs=$out_file_prefix"_usbinfo."$out_format
	out_file_apps_all=$out_file_prefix"_apps-all."$out_format
	out_file_networks=$out_file_prefix"_networks."$out_format
elif [[ $out_format == "txt" ]]; then
	out_file_os=$out_file_prefix"."$out_format
	out_file_users=$out_file_prefix"."$out_format
	out_file_filelist=$out_file_prefix"."$out_format
	out_file_usbs=$out_file_prefix"."$out_format
	out_file_apps_all=$out_file_prefix"."$out_format
	out_file_networks=$out_file_prefix"."$out_format
fi
delete_existing $out_file_os
delete_existing $out_file_users
delete_existing $out_file_filelist
delete_existing $out_file_usbs
delete_existing $out_file_apps_all
delete_existing $out_file_networks

#generating headers for output tables
out_file_os_header="Volume Name|Volume Serial Number|Filesystem|Size(bytes)|Windows Version|Service Pack|Owner|Organisation|Install Date|Hostname|Timezone|Timezone Offset"
out_file_filelist_header="Volume Serial Number|File inode number|Type (dir/file)|Full Path"
out_file_apps_header="Registry Key|User SID|Application|Version|Company|Install Date"
out_file_users_header="Username|SID|Full Name|Comment|Account Created|Last Login|Login Count|Password Set|Password Last Reset|Last Incorrect Password Entry|Password Hint|Flags|Groups"
out_file_usbs_header="USB ID|Name|Serial Number|Parent ID Prefix|Last Mounted As|First Connected|Last Connected|Last Removed|Other Connection Timestamps"
out_file_networks_header="Network Name|Type|First Connected|Last Connected|Default Gateway MAC Address"

#adding extra fields to header if hash (and nist) options selected
if [[ ( "$hash" == true ) ]]; then
	out_file_os_header=$out_file_os_header"|MD5|SHA1"
	out_file_filelist_header=$out_file_filelist_header"|MD5|SHA1"
	
	if [[ ( "$nist" == true ) ]]; then
		out_file_filelist_header=$out_file_filelist_header"|In NIST NSRL?|NIST Category"
	fi
fi

#Getting image type eg. raw or ewf
img_type=$(get_img_type)

#checking if image is physical or logical and processing appropriately
mmls_out=$(mmls -a "$image_file" 2>/dev/null)
if [[ -z $mmls_out ]]; then
	#Logical image
	echo "Processing logical image file:" $image_file
	img_method="logical"
	start_sec=0
	
	#Getting filesystem type (in lowercase)
	fs_type=$(get_fs_type)
	fs_type="${fs_type,,}"
	
	#Getting volume serial number
	vol_sn=$(get_vol_sn)
	
	#running osinfo module, if option selected
	if [[ $modules == *"osinfo"* ]]; then
		echo "Getting OS information..."
		
		if [[ ! -d $dumppath ]]; then
			mkdir -p $dumppath
		fi
		if [[ ! -f $dumppath/SYSTEM ]]; then
			echo "Extracting registry hive HKLM/SYSTEM..."
			extract_file "Windows/system32/config/SYSTEM"
		fi
		if [[ ! -f $dumppath/SOFTWARE ]]; then
			echo "Extracting registry hive HKLM/SOFTWARE..."
			extract_file "Windows/system32/config/SOFTWARE"
		fi
		
		os_info=$(get_volume_info)
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_os_header $out_file_os $out_file_os_header
		else
			#write out report section title for txt file
			write_out "OS Information" $out_file_os ""
		fi
		write_out $os_info $out_file_os $out_file_os_header
	fi
	
	#running users module, if option selected
	if [[ $modules == *"users"* ]]; then
		echo "Getting user information..."	
		
		if [[ ! -d $dumppath ]]; then
			mkdir -p $dumppath
		fi
		if [[ ! -f $dumppath/SAM ]]; then
			echo "Extracting registry hive HKLM/SAM..."
			extract_file "Windows/system32/config/SAM"
		fi
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_users_header $out_file_users $out_file_users_header
		else
			#write out report section title for txt file
			write_out "User Information" $out_file_users ""
		fi
		
		get_user_info
		
		#extracting password hashes if option selected
		if [[ "$passdump" == true ]]; then
			echo "Extracting user password hashes..."	
			if [[ ! -f $dumppath/SYSTEM ]]; then
				echo "Extracting registry hive HKLM/SYSTEM..."
				extract_file "Windows/system32/config/SYSTEM"
			fi
			pwdump $dumppath/SYSTEM $dumppath/SAM > sampwdump.txt
		fi
	fi
	
	#running file list module, if option selected
	if [[ $modules == *"filelist"* ]]; then
		echo "Getting file listing..."	
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_filelist_header $out_file_filelist $out_file_filelist_header
		else
			#write out report section title for txt file
			write_out "File Listing" $out_file_filelist ""
		fi
		
		get_file_list
	fi
	
	#running USB info module, if option selected
	if [[ $modules == *"usbs"* ]]; then
		echo "Getting USB information..."	
		
		if [[ ! -d $dumppath ]]; then
			mkdir -p $dumppath
		fi
		if [[ ! -f $dumppath/SYSTEM ]]; then
			echo "Extracting registry hive HKLM/SYSTEM..."
			extract_file "Windows/system32/config/SYSTEM"
		fi
		if [[ ! -f $dumppath/setupapi.dev.log ]]; then
			echo "Extracting file setupapi.dev.log..."
			extract_file "Windows/INF/setupapi.dev.log"
		fi
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_usbs_header $out_file_usbs $out_file_usbs_header
		else
			#write out report section title for txt file
			write_out "USB Information" $out_file_usbs ""
		fi
		
		get_usb_info
	fi
	
	#running App info module, if option selected
	if [[ $modules == *"apps"* ]]; then
		echo "Getting application information..."	
		
		if [[ ! -d $dumppath ]]; then
			mkdir -p $dumppath
		fi
		if [[ ! -f $dumppath/SOFTWARE ]]; then
			echo "Extracting registry hive HKLM/SOFTWARE..."
			extract_file "Windows/system32/config/SOFTWARE"
		fi
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_apps_header $out_file_apps_all $out_file_apps_header
		else
			#write out report section title for txt file
			write_out "Applications Installed" $out_file_apps_all ""
		fi
		
		get_apps
	fi
	
	#running Network info module, if option selected
	if [[ $modules == *"networks"* ]]; then
		echo "Getting network information..."	
		
		if [[ ! -d $dumppath ]]; then
			mkdir -p $dumppath
		fi
		if [[ ! -f $dumppath/SOFTWARE ]]; then
			echo "Extracting registry hive HKLM/SOFTWARE..."
			extract_file "Windows/system32/config/SOFTWARE"
		fi
		
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_networks_header $out_file_networks $out_file_networks_header
		else
			#write out report section title for txt file
			write_out "Network Connections" $out_file_networks ""
		fi
		
		get_network_info
	fi
	
else
	#Physical image
	echo "Processing physical image file:" $image_file
	img_method="physical"
	
	#writing out header information for output files depending on selected format
	if [[ $modules == *"osinfo"* ]]; then
		if [[ $out_format == "tsv" ]]; then
			write_out $out_file_os_header $out_file_os $out_file_os_header
		else
			#write out report section title for txt file
			write_out "OS Information" $out_file_os ""
		fi
	fi
	
	#looping through volumes
	for mm_line in $mmls_out; do
		if [[ $mm_line =~ ^[[:digit:]][[:digit:]][[:digit:]]:* ]]; then
			start_sec=$(echo $mm_line | sed 's/ \+/ /g' | cut -d' ' -f3)
			
			#Getting filesystem type (in lowercase)
			fs_type=$(get_fs_type)
			fs_type="${fs_type,,}"
			
			#Getting volume serial number
			vol_sn=$(get_vol_sn)
			
			#running OS info module, if selected
			if [[ $modules == *"osinfo"* ]]; then
				if [[ "$(is_windows_volume)" == true ]]; then
					if [[ ! -d $dumppath ]]; then
						mkdir -p $dumppath
					fi
					if [[ ! -f $dumppath/SYSTEM ]]; then
						echo "Extracting registry hive HKLM/SYSTEM..."
						extract_file "Windows/System32/config/SYSTEM"
					fi
					if [[ ! -f $dumppath/SOFTWARE ]]; then
						echo "Extracting registry hive HKLM/SOFTWARE..."
						extract_file "Windows/system32/config/SOFTWARE"
					fi
				fi
				
				echo "Getting OS information for volume S/N" $vol_sn"..."	
				os_info=$(get_volume_info_from_mmls $mm_line)
				write_out $os_info $out_file_os $out_file_os_header
			fi
			
			#running users module, if option selected
			if [[ ( $modules == *"users"* ) && ( "$(is_windows_volume)" == true ) ]]; then
				echo "Getting user information..."	
				if [[ ! -d $dumppath ]]; then
					mkdir -p $dumppath
				fi
				if [[ ! -f $dumppath/SAM ]]; then
					echo "Extracting registry hive HKLM/SAM..."
					extract_file "Windows/system32/config/SAM"
				fi
			
				if [[ $out_format == "tsv" ]]; then
					write_out $out_file_users_header $out_file_users $out_file_users_header
				else
					#write out report section title for txt file
					write_out "User Information" $out_file_users ""
				fi
			
				get_user_info
				
				#extracting password hashes if option selected
				if [[ "$passdump" == true ]]; then
					echo "Extracting user password hashes..."	
					if [[ ! -f $dumppath/SYSTEM ]]; then
						echo "Extracting registry hive HKLM/SYSTEM..."
						extract_file "Windows/system32/config/SYSTEM"
					fi
					pwdump $dumppath/SYSTEM $dumppath/SAM > sampwdump.txt
				fi
			fi
			
			#running file list module, if option selected
			if [[ ( $modules == *"filelist"* ) ]]; then
				echo "Getting file listing for volume S/N" $vol_sn"..."	

				if [[ $out_format == "tsv" ]]; then
					write_out $out_file_filelist_header $out_file_filelist $out_file_filelist_header
				else
					#write out report section title for txt file
					write_out "File Listing" $out_file_filelist ""
				fi
			
				get_file_list
			fi
			
			#running USB info module, if option selected
			if [[ ( $modules == *"usbs"* ) && ( "$(is_windows_volume)" == true ) ]]; then
				echo "Getting USB information..."	
				
				if [[ ! -d $dumppath ]]; then
					mkdir -p $dumppath
				fi
				if [[ ! -f $dumppath/SYSTEM ]]; then
					echo "Extracting registry hive HKLM/SYSTEM..."
					extract_file "Windows/system32/config/SYSTEM"
				fi
				if [[ ! -f $dumppath/setupapi.dev.log ]]; then
					echo "Extracting file setupapi.dev.log..."
					extract_file "Windows/INF/setupapi.dev.log"
				fi
				
				if [[ $out_format == "tsv" ]]; then
					write_out $out_file_usbs_header $out_file_usbs $out_file_usbs_header
				else
					#write out report section title for txt file
					write_out "USB Information" $out_file_usbs ""
				fi
				
				get_usb_info
			fi
			
			#running App info module, if option selected
			if [[ ( $modules == *"apps"* ) && ( "$(is_windows_volume)" == true ) ]]; then
				echo "Getting application information..."	
				
				if [[ ! -d $dumppath ]]; then
					mkdir -p $dumppath
				fi
				if [[ ! -f $dumppath/SOFTWARE ]]; then
					echo "Extracting registry hive HKLM/SOFTWARE..."
					extract_file "Windows/system32/config/SOFTWARE"
				fi
				
				if [[ $out_format == "tsv" ]]; then
					write_out $out_file_apps_header $out_file_apps_all $out_file_apps_header
				else
					#write out report section title for txt file
					write_out "Applications Installed" $out_file_apps_all ""
				fi
				
				get_apps
			fi
			
			#running Network info module, if option selected
			if [[ ( $modules == *"networks"* ) && ( "$(is_windows_volume)" == true ) ]]; then
				echo "Getting network information..."	
				
				if [[ ! -d $dumppath ]]; then
					mkdir -p $dumppath
				fi
				if [[ ! -f $dumppath/SOFTWARE ]]; then
					echo "Extracting registry hive HKLM/SOFTWARE..."
					extract_file "Windows/system32/config/SOFTWARE"
				fi
				
				if [[ $out_format == "tsv" ]]; then
					write_out $out_file_networks_header $out_file_networks $out_file_networks_header
				else
					#write out report section title for txt file
					write_out "Network Connections" $out_file_networks ""
				fi
				
				get_network_info
			fi
		fi
	done
fi

#cleaning up temporary directory if 'keep' option not selected
if [[ ( -d $dumppath ) && ( "$keep" == false ) ]]; then
	rm -r $dumppath
fi
		
#resetting field separator
IFS=$OLDIFS

