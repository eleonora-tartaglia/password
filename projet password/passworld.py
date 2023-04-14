#####################################################################################################################################################           
                    # ECRIRE UN PROGRAMME QUI DEMANDE DE CHOISIR UN MOT DE PASSE ET VERIFIER SI CE MOT DE PASSE REPOND A CERTAINS CRITERES
#####################################################################################################################################################

import re

password = input("Veuillez entrer votre password ")

while True:

    if len(password) < 8:
        print("Le password doit contenir au moins 8 caractères")
    
    else:   
        
        if  not re.search(r"[A-Z]", password):
            print("Le password doit contenir au moins une lettre majuscule")
        elif not re.search(r'[a-z]', password):
            print("Le password doit contenir au moins une lettre miniscule")
        elif not re.search(r'[0-9]', password):
            print("Le password doit contenir au moins un chiffre")
        elif not re.search(r'[!, @, #, $, %, ^, &, *]', password):
            print("Le passeword doit contenir au moins un caractère spécial")
        else:
            print("\n\t\t\t\t\t\t\tSésame ouvre toi")

    break

#####################################################################################################################################################
                                    # ECRIRE UN PROGRAMME QUI CRYPTE LE MOT DE PASSE QUE L'UTILISATEUR A ENTRE PRECEDEMMENT
#####################################################################################################################################################

import hashlib

password_crypt = hashlib.sha256(password.encode('utf-8'))
cypher = password_crypt.hexdigest()

print("\npassword :", password)
print("\ncypher :", cypher)

#######################################################################################################################################################
        # CREER UN PROGRAMME QUI PERMET DE GERER LES MOTS DE PASSE RENSEIGNES PAR L'UTILISATEUR EN LES ENREGISTRANT SOUS FORME HACHEE DANS UN FICHIER
#######################################################################################################################################################

import json

passwords = {"passwords_crypt" : cypher
             }

def hash_password():
    return cypher

def save_passwords(passwords):
    with open('passwords_file.json', 'w') as f:
        json.dump(passwords, f)

def load_passwords():
    try:
        with open('passwords_file.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def add_password():
    new_password = input("\nEntrer un new password : ")
    hashed_password = hash_password(new_password)
    passwords[new_password] = hashed_password
    
loaded_passwords = load_passwords()

save_passwords(passwords)
print("\nEurêka !!!! Les passwords sont rangés au coffre")

def show_passwords():
    passwords = load_passwords()
    if not passwords:
        print("Saperlipopette I feel empty")
    else:
        for new_password, credentials in passwords.items():
            password = credentials['password']
            print(f"New Password: {new_password}\nPassword: {password}\n")

def main():
    while True:
        print("\n\t\t\t\t\t\tWhat do you want of me ?")
        print("\n\t\t\t\t\t\t1. Ajouter un new password ?")
        print("\n\t\t\t\t\t\t2. Que je te montre ceux dans le coffre ?")
        print("\n\t\t\t\t\t\t3. Ou bien tu veux déjà me quitter ?")
        choice = input("\n\n\t\t\t\t\t\tQuelle est ta reponse mon lapin ?")
        
        if choice == '1':
            add_password()
        elif choice == '2':
            show_passwords()
        elif choice == '3':
            break
        else:
            print("\n\t\t\tMauvaise reponse tu files du mauvais coton.. mais bon je te laisse une seconde chance.. \n\n\t\t\t\t\t\t\tTry again :) ")

if __name__ == '__main__':
    main()

