# register-key

Un fichier `.pem` par compte, nomme `<nom-utilisateur>-<horodatage>.pem`.

Chaque fichier contient deux blocs :

- `SN CERTIFICATE` : public. Les donnees personnelles sont lisibles en
  en-tete, et le corps signe par le RA fait foi.
- `SN ENCRYPTED PRIVATE KEY` : les cles privees, chiffrees par le mot de
  passe du titulaire (scrypt + AES-256-GCM).

Ces fichiers ne sont pas versionnes. Pour partager son identite sans sa
cle privee :

    ./sn-cli account export --as <email> -o mon-certificat.pem
