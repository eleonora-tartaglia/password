#####################################################################################################################################################           
                    # ECRIRE UN PROGRAMME QUI DEMANDE DE CHOISIR UN MOT DE PASSE ET VERIFIER SI CE MOT DE PASSE REPOND A CERTAINS CRITERES
#####################################################################################################################################################

import re

def check_password(password):
    if len(password) < 8:
        print("Ça ne va pas le faire.. il faut au moins 8 caractères")
        return False
    
    if not re.search(r'[a-z]', password):
        print("Ça ne va pas le faire, je ne vois pas de lettre minuscule")
        return False
    
    if not re.search(r'[A-Z]', password):
        print("Ça ne va pas le faire, je ne vois pas de lettre majuscule")
        return False
    
    if not re.search(r'[0-9]', password):
        print("Ça ne va pas le faire, je ne vois pas de chiffre")
        return False
    
    if not re.search(r'[!, @, #, $, %, ^, &, *]', password):
        print("Ça ne va pas le faire, je ne vois pas de caractère spécial")
        return False
    
    return True

password = input("Tapote ton password : ")

while not check_password(password):
    password = input("Retapote un new password : ")

print()
print("Le password est à mon gout")

'''stock_password_file = "passwords.txt"
while True:
    m_d_p = input("Entrez votre mot de passe : ")
    if check_password(m_d_p):
        m_d_p_hash = hashlib.sha256(m_d_p.encode("utf-8")).hexdigest()
        with open(stock_password_file, "r") as f:
            if m_d_p_hash in f.read():
                print("Mot de passe déjà enregistré.")
            else:
                with open(stock_password_file, "a") as f:
                    f.write(m_d_p_hash + "\n")
                    print("Mot de passe ajouté avec succès.")
            break
    else:
        print("Le mot de passe doit contenir au moins 8 caractères, une lettre minuscule, une lettre majuscule, un chiffre et un caractère spécial.")
'''

#####################################################################################################################################################
                                    # ECRIRE UN PROGRAMME QUI CRYPTE LE MOT DE PASSE QUE L'UTILISATEUR A ENTRE PRECEDEMMENT
#####################################################################################################################################################

import hashlib

password_crypt = hashlib.sha256(password.encode('utf-8'))
cypher = password_crypt.hexdigest()

#######################################################################################################################################################
        # CREER UN PROGRAMME QUI PERMET DE GERER LES MOTS DE PASSE RENSEIGNES PAR L'UTILISATEUR EN LES ENREGISTRANT SOUS FORME HACHEE DANS UN FICHIER
#######################################################################################################################################################

import json

passwords = {"passwords_crypt" : cypher
             }

def hash_password(password: str) -> str:
    password_crypt = hashlib.sha256(password.encode('utf-8'))
    cypher = password_crypt.hexdigest()
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
    global passwords
    passwords = load_passwords()
    new_password = input("\nTapote un new password : ")
    hashed_password = hash_password(new_password)
    passwords[new_password] = {"password": hashed_password}
    save_passwords(passwords)

loaded_passwords = load_passwords()

save_passwords(passwords)
print("Le password a été correctement rangé au coffre")

def show_passwords():
    loaded_passwords = load_passwords()
    if not loaded_passwords:
        print("Saperlipopette I feel empty")
    else:
        for new_password, credentials in loaded_passwords.items():
            password = credentials
            print(f"New Password: {new_password}\nPassword: {password}\n")

def main():
    while True:
        print("\n\t\t\t\t\t\tNow, what do you want of me ?")
        print("\n\t\t\t\t\t\t1. Ajouter un new password ?")
        print("\n\t\t\t\t\t\t2. Que je te montre ce qu'il y a dans mon coffre ?")
        print("\n\t\t\t\t\t\t3. Ou bien tu veux déjà me quitter ?")
        choice = input("\n\n\t\t\t\t\t\tQuelle est ta reponse mon lapin ?")
        
        if choice == '1':
            passwords = load_passwords()
            add_password()
            save_passwords(passwords)
            print("\n\t\t\tIt's okay !")
            input("\nAppuie sur Enter si tu veux continuer de jouer avec moi...")
        elif choice == '2':
            show_passwords()
            print("\n\t\t\tIt's okay !")
            input("\nAppuie sur Enter si tu veux continuer de jouer avec moi...")
        elif choice == '3':
            break
        else:
            print("\n\t\t\tMauvaise réponse tu files du mauvais toton.. mais bon je te laisse une seconde chance.. \n\n\t\t\t\t\t\t\tTry again :) ")

if __name__ == '__main__':
    main()