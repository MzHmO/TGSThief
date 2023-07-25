# TGSThief
I think a lot of people have seen the project https://github.com/foxlox/GIUDA . It is an interesting way to get the TGS of a user whose logon session is just present on the computer. The problem is that its code is written in Pascal (the last time I wrote in Pascal was at school), so I had to rewrite the project in C++. 

## How to use
Just run the tool and select the desired logon session! The tool will automatically escalate privileges and request a TGS:
![изображение](https://github.com/MzHmO/TGSThief/assets/92790655/ed847df4-d95f-48d5-8071-dafea3b86676)


## Advantages
I consider the following to be certain advantages of my project:
1. We do not need to run the code on behalf of the system. Run the program as a local administrator, the privilege escalation will happen automatically. 
2. I also added SPN validation through regex, so there is less chance of making a mistake and not getting TGS.
3. The TGS ticket is optionally injected into the logon session where the tool is running. The TGS ticket is simply output in base64 for convenience, and only embedded if required.
4. It is not necessary to run the tool ten times to see the LUID. You can now select the LUID you want from the drop down list.

## How It Works
First comes the standard privilege escalation to the system via the thread token mechanism (`ImpersonateSelf()` + `ImpersonateLoggedOnUser()`). Next, the logon process is registered via `LsaRegisterLogonProcess()`, just the `SeTcbPrivilege` is required to successfully call this function. After successful registration of the login process, we receive the AP Kerberos ID.  Implemented via `LsaLookupAuthenticationPackage()`. Additionally, my program remembers the LUID of the session from which it is run. This is done for future ticket injection. The current LUID can be obtained from the token by calling `GetTokenInformation()`:
![изображение](https://github.com/MzHmO/TGSThief/assets/92790655/441e4522-8245-4ff3-9600-e9a16e80a0fa)

Note that I initialize the HighPart and LowPart elements with values of 0. In case of an error, the ticket will be injected into the session on behalf of which the tool is launched. Since I have provided privilege escalation, in case of an error, the ticket is injected into the system's LOGON session. But this function works stable, so this situation should not happen. In any case, the ticket is still output in Base64 format, you can inject it using the injector.ps1 tool (https://github.com/MzHmO/PowershellKerberos).

The user must then enter the SPN for which the TGS is to be requested. This SPN is then passed to the `LsaCallAuthenticationPackage()` function call, which results in a TGS ticket request. Note that we have initialized the LogonId element of the KERB_RETRIEVE_TKT_REQUEST structure with the value that the user has chosen. This value is the LUID of the session from which the TGS should be requested. As a result, we get a TGS ticket for the desired service as if the user himself wanted to access it.
![изображение](https://github.com/MzHmO/TGSThief/assets/92790655/e8294213-f1e8-40cd-8d48-28a008303f75)

Additionally, I've added a Test function that you can use to verify that the handle on the LSA, AP ID and LogonID are correct.
![изображение](https://github.com/MzHmO/TGSThief/assets/92790655/993a0c39-f331-4000-b45b-d4fc44438981)


## Why don't you just dump TGT?
Modern SIEMs know how to detect a Pass The Ticket attack when a TGT ticket is passed in. 

This is based on the fact that the SIEM (or other defensive tool) remembers the IP address that the TGT ticket was issued to. And then, when a TGS request is made, it compares the IP address of the device from which the TGS request was made to the device to which the TGT was issued. If the IP addresses are different, a Pass The Ticket attack is most likely being used.

TGSThief is a bit more stealthy in this regard. Because we request a TGS using a legitimate TGT from the user's logon session. And Pass The Ticket using TGS is much quieter because we are only interacting with the service and not the KDC.



