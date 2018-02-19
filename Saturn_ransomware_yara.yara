rule Sat{
    meta:
      author ="Gajanand Rao Surve"
      desc="Matches very first unpacked sample of saturn ransomware"
    strings:
    $dll="SbieDll.dll" wide ascii nocase
    $cm="vssadmin.exe delete shadows" wide ascii nocase
    $nam="DECRYPT_MY_FILES#.vbs" wide ascii nocase
    $fi="DECRYPT_MY_FILES.BMP"
    $FuN="S A T U R N" wide ascii
 condition:
     all of them
}
