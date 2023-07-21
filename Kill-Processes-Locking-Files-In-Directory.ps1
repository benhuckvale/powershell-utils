<#
.SYNOPSIS
    List or kill processes locking files within a directory

.DESCRIPTION
    Kill-Processes-Locking-Files-In-Directory takes a directory and calls a
    function that returns a System.Collections.Generic.List of
    System.Diagnostic.Process objects (one or more processes could have a lock
    on a specific file, which is why a List is used) for any processes that
    hold a lock on a file at any depth within the directory given.
    The default behaviour is to list the processes found holding locks. If the
    -Kill switch is used, then StopProcess is called on these processes.

.NOTES
    Windows solution credit to: https://stackoverflow.com/a/20623311
    Was originally: https://github.com/pldmgg/misc-powershell/blob/934df578de8c40b498fc2caf12b26c76fe990885/MyFunctions/PowerShellCore_Compatible/Get-FileLockProcess.ps1
    That script was just to find what process was locking a file. This is an
    adaptation and extension of that script to allow for searching an entire
    directory and providing the option to kill.

.PARAMETER Directory
    This parameter is MANDATORY.

    This parameter takes a string that represents a full path to a directory

.EXAMPLE
    PS C:\Users\testadmin> Kill-Processes-Locking-Files-In-Directory "C:/gitlab-runner/builds"

    Process ID: 12348, Name: python
    Process ID: 13572, Name: python

    PS C:\Users\testadmin> Kill-Processes-Locking-Files-In-Directory.ps1 "C:/gitlab-runner/builds" -Kill

    Process ID: 12348, Name: python - Killed
    Process ID: 13572, Name: python - Killed
#>

param (
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$DirectoryPath,
    [switch]$Kill
)

function Get-Processes-Locking-Files-In-Directory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    if (! $(Test-Path $DirectoryPath)) {
        Write-Error "The path $DirectoryPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Add-Type -TypeDefinition @'
        using System.Collections.Generic;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.InteropServices;
        using System;

        namespace FileLockUtil
        {
            public static class ProcessesLockingFilesInDirectory
            {
                [StructLayout(LayoutKind.Sequential)]
                public struct RM_UNIQUE_PROCESS
                {
                    public int dwProcessId;
                    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
                }

                const int RmRebootReasonNone = 0;
                const int CCH_RM_MAX_APP_NAME = 255;
                const int CCH_RM_MAX_SVC_NAME = 63;

                enum RM_APP_TYPE
                {
                    RmUnknownApp = 0,
                    RmMainWindow = 1,
                    RmOtherWindow = 2,
                    RmService = 3,
                    RmExplorer = 4,
                    RmConsole = 5,
                    RmCritical = 1000
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                struct RM_PROCESS_INFO
                {
                    public RM_UNIQUE_PROCESS Process;

                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
                    public string strAppName;

                    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
                    public string strServiceShortName;

                    public RM_APP_TYPE ApplicationType;
                    public uint AppStatus;
                    public uint TSSessionId;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool bRestartable;
                }

                [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
                static extern int RmRegisterResources(uint pSessionHandle,
                                                      UInt32 nFiles,
                                                      string[] rgsFilenames,
                                                      UInt32 nApplications,
                                                      [In] RM_UNIQUE_PROCESS[] rgApplications,
                                                      UInt32 nServices,
                                                      string[] rgsServiceNames);

                [DllImport("rstrtmgr.dll", CharSet = CharSet.Auto)]
                static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

                [DllImport("rstrtmgr.dll")]
                static extern int RmEndSession(uint pSessionHandle);

                [DllImport("rstrtmgr.dll")]
                static extern int RmGetList(uint dwSessionHandle,
                                            out uint pnProcInfoNeeded,
                                            ref uint pnProcInfo,
                                            [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
                                            ref uint lpdwRebootReasons);

                /// <summary>
                /// Find out what process(es) have a lock on the files at any depth within the specified directory path.
                /// </summary>
                /// <param name="directoryPath">Path to Directory under which locked files should be identified</param>
                /// <returns>Any processes locking files within that directory</returns>
                /// <remarks>See also:
                /// http://msdn.microsoft.com/en-us/library/windows/desktop/aa373661(v=vs.85).aspx
                /// http://wyupdate.googlecode.com/svn-history/r401/trunk/frmFilesInUse.cs (no copyright in code at time of viewing)
                ///
                /// </remarks>
                public static List<Process> WhoIsLockingWithin(string directoryPath)
                {
                    uint handle;
                    string key = Guid.NewGuid().ToString();
                    List<Process> processes = new List<Process>();

                    int res = RmStartSession(out handle, 0, key);
                    if (res != 0)
                    {
                        throw new Exception("Could not begin restart session.  Unable to determine file locker.");
                    }

                    try
                    {
                        const int ERROR_MORE_DATA = 234;
                        uint pnProcInfoNeeded = 0;
                        uint pnProcInfo = 0;
                        uint lpdwRebootReasons = RmRebootReasonNone;

                        string[] files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories);

                        res = RmRegisterResources(handle, (uint)files.Length, files, 0, null, 0, null);

                        if (res != 0)
                        {
                            throw new Exception("Could not register resource.");
                        }

                        //Note: there's a race condition here -- the first call to RmGetList() returns
                        //      the total number of process. However, when we call RmGetList() again to get
                        //      the actual processes this number may have increased.
                        res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);

                        if (res == ERROR_MORE_DATA)
                        {
                            RM_PROCESS_INFO[] processInfo = new RM_PROCESS_INFO[pnProcInfoNeeded];
                            pnProcInfo = pnProcInfoNeeded;

                            // Get the list
                            res = RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                            if (res == 0)
                            {
                                processes = new List<Process>((int)pnProcInfo);

                                // Enumerate all of the results and add them to the
                                // list to be returned
                                for (int i = 0; i < pnProcInfo; i++)
                                {
                                    try
                                    {
                                        processes.Add(Process.GetProcessById(processInfo[i].Process.dwProcessId));
                                    }
                                    catch (ArgumentException) { }
                                }
                            }
                            else
                            {
                                throw new Exception("Could not list processes locking resource.");
                            }
                        }
                        else if (res != 0)
                        {
                            throw new Exception("Could not list processes locking resource. Failed to get size of result.");
                        }
                    }
                    finally
                    {
                        RmEndSession(handle);
                    }

                    return processes;
                }
            }
        }
'@

    try {
        $lockingProcesses = [FileLockUtil.ProcessesLockingFilesInDirectory]::WhoIsLockingWithin($DirectoryPath)
        $lockingProcesses
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

$lockingProcesses = Get-Processes-Locking-Files-In-Directory -DirectoryPath $DirectoryPath

foreach ($process in $lockingProcesses) {
    $processId = $process.Id
    $processName = $process.Name

    Write-Host -NoNewLine "Process ID: $processId, Name: $processName"

    # Kill the process if the -Kill switch is specified
    if ($Kill) {
        try {
            Stop-Process -Id $processId -ErrorAction Stop
            Write-Host " - Killed"
        }
        catch {
            Write-Host " - Failed to kill the process: $_"
        }
    } else {
        Write-Host ""
    }
}

