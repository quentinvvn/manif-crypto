# manif_crypto

Noyau de sécurité ouvert de l'application Manif'. L'application est fermée ; ce paquet est publié pour que chacun puisse vérifier comment les données des manifestants sont protégées.

## Ce que contient ce paquet

- Génération des clés sur l'appareil et phrase de récupération.
- Chiffrement de chaque segment vidéo avant envoi : le serveur ne reçoit jamais un original en clair.
- Chaîne d'empreintes SHA-256 des segments.
- Vérification des preuves d'horodatage (OpenTimestamps, RFC 3161).

## Ce qui n'est pas ici

- La messagerie de groupe : elle repose sur le protocole Matrix et son SDK, déjà open source.
- L'interface et le reste de l'application.

## Vérifier une preuve

Le certificat PDF délivré par l'application renvoie à ce paquet : la procédure de vérification peut être rejouée avec lui, sans l'application.

## Signaler une faille

Utiliser l'onglet « Security » de ce dépôt (Report a vulnerability). Merci de ne pas publier la faille avant correction.

## Licence

Apache 2.0, voir `LICENSE`.
