Powershell-utils
================

Utility scripts for windows written in powershell with any embedded .NET code as needed

Why
---

This project exists because of my love of eliminating dependencies.
I am not particularly a powershell advocate but I do think it is neat that you
can use many .NET classes and methods directly without needing Visual Studio to
build. It is one way of accomplishing more on windows without having to install
anything. After using things like python (or perl) on Linux or OS X to
accomplish sysadmin stuff, one might reach for the same on Windows but there is a strong
argument not to and use powershell, simply to remove that dependency. So in
pursuit of that here I will collect powershell scripts I come across or come up with.
Although I've only got one thing here at the moment.

Kill-Processes-Locking-Files-In-Directory
-----------------------------------------

This ia a powershell script to kill processes that have open file handles within a
particular directory.

To pull this together I used principally this [Get-FileLockProcess.ps1](https://github.com/pldmgg/misc-powershell/blob/master/MyFunctions/PowerShellCore_Compatible/Get-FileLockProcess.ps1)
script which was based on this [stackoverflow post asking how to find processes that are locking files](https://stackoverflow.com/questions/317071/how-do-i-find-out-which-process-is-locking-a-file-using-net/20623311#20623311).

I noted that other solutions for finding processes holding files open involved:
- Using `handle.exe` - but that's not available on the system by default.
- Using `openfiles` - but that requires enabling (`openfiles /local on`) and a reboot, and it slows down system performance.
- Other techniques ... that had issues.

This powershell script for finding such processes is neat as it requires no
other dependencies or prerequisite actions.

My adaptations are then to make it work to identify all processes locking any files
within a directory, and then make it possible to kill them.
