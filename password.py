import re
import hashlib
import json

print ("Veuillez entrer votre mot de passe")
def valider_password(mot_de_passe):
 if len(mot_de_passe)<8:
  return False
 if not re.search("[a-z]",mot_de_passe):
    return False
 if not re.search("[A-Z]",mot_de_passe):
    return False
 if not re.search("[0-9]",mot_de_passe):
    return False
 if not (["@","&","!","#", "$", "%","^", "*"],mot_de_passe):
    return False
 return True



  


mot_de_passe=input()

if valider_password(mot_de_passe):
 p=1
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=2
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=3
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=4
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 print ("mot de passe valider")
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
  reponse=input("voulez vous enregistrer votre mot de passe 'oui' ou 'non':")
if reponse=="oui":
 hash_object=hashlib.sha256(mot_de_passe.encode())
 hash_value=hash_object.hexdigest()
 stocker_mot_de_passe={"hash_value":hash_value}
 with open ("stockage de mot de passe.json","w") as f:
   json.dump(stocker_mot_de_passe,f)
elif reponse=="non":
  print("aurevoir")







print ("Veuillez entrer votre mot de passe")
mot_de_passe=input()

if valider_password(mot_de_passe):
 p=1
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=2
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=3
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=4
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 print ("mot de passe valider")
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
  reponse=input("voulez vous enregistrer votre mot de passe 'oui' ou 'non':")
if reponse=="oui":
 hash_object=hashlib.sha256(mot_de_passe.encode())
 hash_value=hash_object.hexdigest()
 stocker_mot_de_passe={"hash_value":hash_value}
 with open ("stockage de mot de passe.json","w") as f:
   json.dump(stocker_mot_de_passe,f)
elif reponse=="non":
  print("aurevoir")
 
  
  
  





print ("Veuillez entrer votre mot de passe")
mot_de_passe=input()

if valider_password(mot_de_passe):
 p=1
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=2
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=3
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 p=4
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
 print ("mot de passe valider")
else:
 print ("mot de passe invalide ")
 print ("● Il doit contenir au moins 8 caractères.")
 print ("● Il doit contenir au moins une lettre majuscule.")
 print ("● Il doit contenir au moins une lettre minuscule.")
 print ("● Il doit contenir au moins un chiffre.")
 print ("● Il doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
 print ("● Veuillez entrer votre mot de passe :")
 mot_de_passe=input()
if valider_password(mot_de_passe):
  reponse=input("voulez vous enregistrer votre mot de passe 'oui' ou 'non':")
if reponse=="oui":
 hash_object=hashlib.sha256(mot_de_passe.encode())
 hash_value=hash_object.hexdigest()
 stocker_mot_de_passe={"hash_value":hash_value}
 with open ("stockage de mot de passe.json","w") as f:
   json.dump(stocker_mot_de_passe,f)
elif reponse=="non":
  print("aurevoir")
 
  