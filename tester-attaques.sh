#!/bin/sh
# Batterie complete : signature, fabrication des faux, verification.
# Chaque commande est affichee avant d'etre executee.
#
#   ./tester-attaques.sh
#
# Le mot de passe du compte signataire est demande une fois, ou pris
# dans SN_PASSWORD.
cd "$(dirname "$0")" || exit 1

PDF=letter_attestation_rang.pdf
SIGNE=letter_attestation_rang-signe.pdf
COMPTE=$(ls register-key/fatou-ndiaye-*.pem 2>/dev/null | head -1)
CERT=fatou-certificat-public.pem

[ -z "$COMPTE" ] && { echo "aucun compte fatou-ndiaye dans register-key/"; exit 1; }

if [ -z "$SN_PASSWORD" ]; then
    printf 'mot de passe du compte signataire : '
    stty -echo; read -r SN_PASSWORD; stty echo; echo
    export SN_PASSWORD
fi

cmd() {
    printf '\033[2m$ %s\033[0m\n' "$*"
    "$@"
    printf '\033[2m  → exit %s\033[0m\n' "$?"
}
titre() { printf '\n\033[1m══ %s\033[0m\n' "$1"; }

titre "1. SIGNER"
cmd ./sn-cli sign "$PDF" --pdf --cert "$COMPTE" \
    --title "Attestation de rang" --ref "No 007/26"

titre "2. EXPORTER LE CERTIFICAT PUBLIC"
cmd ./sn-cli account export --cert register-key/fatou-ndiaye-20261009T211004.pem -o "$CERT"

titre "3. VERIFIER — doit PASSER"
cmd ./sn-cli verify "$SIGNE" --pdf --cert "$CERT"

titre "4. FABRIQUER LES FAUX"
cmd .venv/bin/python fabriquer-fakes.py "$SIGNE" "$PDF"

titre "5. ATTAQUE — un octet modifie dans la zone signee"
cmd ./sn-cli verify fake-1-octet.pdf --pdf --cert "$CERT"

titre "6. ATTAQUE — bandeau ajoute par-dessus (PDF shadow attack)"
cmd ./sn-cli verify fake-2-overlay.pdf --pdf --cert "$CERT"

titre "7. ATTAQUE — fichier tronque"
cmd ./sn-cli verify fake-3-tronque.pdf --pdf --cert "$CERT"

titre "8. ATTAQUE — original modifie avant signature, vrai QR recolle"
cmd ./sn-cli verify fake-4-original-modifie-signe.pdf --pdf --cert "$CERT"

titre "9. ATTAQUE — QR + bandeau dans UNE SEULE revision"
cmd ./sn-cli verify fake-6-fusion-bandeau.pdf --pdf --cert "$CERT"

titre "10. ATTAQUE — QR + JavaScript dans UNE SEULE revision"
cmd ./sn-cli verify fake-7-fusion-javascript.pdf --pdf --cert "$CERT"

titre "11. ATTAQUE — JavaScript injecte"
cmd ./sn-cli verify fake-8-javascript.pdf --pdf --cert "$CERT"

titre "12. ATTAQUE — lien de phishing invisible"
cmd ./sn-cli verify fake-9-lien-invisible.pdf --pdf --cert "$CERT"

titre "13. ATTAQUE — piece jointe malveillante"
cmd ./sn-cli verify fake-10-piece-jointe.pdf --pdf --cert "$CERT"

titre "14. ATTAQUE — certificat aux en-tetes maquilles"
cmd ./sn-cli ra verify fake-5-certificat.pem

titre "15. ATTAQUE — certificat de quelqu'un d'autre"
cmd ./sn-cli account export --cert register-key/rosly-mamakem-20261009T211003.pem -o fake-autre-signataire.pem
cmd ./sn-cli verify "$SIGNE" --pdf --cert fake-autre-signataire.pem

titre "16. PDF sans aucune preuve"
cmd ./sn-cli verify "$PDF" --pdf
