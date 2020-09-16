# Digital-Software-License

An example digital software licensing system without using a dedicated back-end server. Programmed using C# and FluentFTP. 

## Use case

Any hobbyists or amateur programmers wanting to sell software online, but do not have the time/money to invest in a dedicated back-end server for authentication. 

## Process

1. Authenticate with FTP server using FluentFTP
2. Check for saved "key" from previous activation. If not, read key and save it.
3. Search for key file on FTP server.
4. Get device MacAddress and disk serial. 
5. Check if key has been activated. Step 6 if activated, step 7 if not. 
6. Authenticate details by comparing device mac/serial with mac/serial stored online. Process finished. 
7. Edit license file with current device information (device mac / device serial). Process finished. 

## Vulnerabilities

Vulnerable to reverse engineering and/or memory manipulation. 

Use of a "isValid" bool, which can be manipulated at runtime. 

## Mitigation

1. Declaring variables as internal static readonly strings, preventing simple "string search" of sensitive information using tools such as IDA pro. 
2. Use of cryptographic tokens as tokens for cryptographic encryption algorithms and storing encrypted strings in memory, decreasing chance of finding and decrypting sensitive information.
3. Possible obfuscation (not implemented) of program using VMprotect etc. to protect against dynamic/static analysis or general reverse engineering.
