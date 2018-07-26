rule NJRat
{
	meta:
		author = " Gajanand Rao Surve"
		filetype = "exe"
 
	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide

	condition:
		all of ($s*) and any of ($v*)
}
