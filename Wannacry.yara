rule wannacry_detector {

    meta:
        author = "Alessio Ragazzi"
        created_on = "18/01/2023"
        last_updated = "18/01/2023"
        description = "Basic yara rules to detect the ransomware WannaCry. Rules are based on the strings that I was able to pull during basic static analysis of the binary"

    strings:
        $executable1 = "tasksche.exe"
        $executable2 = "taskdl.exe"
        $string1 = "mssecsvc2.0"
        $string2 = "wannacry"
        $string3 = "wanadecryptor"
        $url1= "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea"

    condition:
        $executable1 and ($executable2 and $string1) or
        $string2 and $executable1 or 
        $string3 and $executable1 or
        $url1 and ($executable1 or $executable1 or $string1 or $string2 or $string3)
}