# AuthX

Compania fictivă **AuthX** utilizează o aplicație web pentru a gestiona accesul la resurse sensibile al angajaților săi. Aplicația salvează datele utilizatorilor, biletele stocate și monitorizează activitățile prin **Audit Logs**.


## Descriere

Un utilizator este recunoscut din momentul înregistrării în platformă prin **formularul de register**, iar apoi cu aceste date se poate loga prin **formularul de login**.

Utilizatorii sunt înregistrați cu unul dintre următoarele roluri:

| Rol | Permisiuni |
|-----|-----------|
| `ANALYST` | Vizualizarea și editarea propriilor bilete, editarea profilului, reset password |
| `MANAGER` | Vizualizarea și editarea propriilor bilete, editarea profilului, vizualizarea activităților, a tuturor biletelor, adăugarea de bilete noi și asignarea lor oricărui utilizator, reset password |


## Structura ramurilor

Acest repository conține două ramuri principale cu scopuri educaționale:

- **`vulnerable-version`** — versiunea inițială a aplicației, care conține **vulnerabilități de securitate intenționate** (ex: SQL Injection, IDOR, lipsă autorizare etc.). Această ramură există pentru a demonstra cum *nu* trebuie scris codul.
- **`fixed-version`** — versiunea corectată, în care vulnerabilitățile au fost remediate urmând bunele practici de securitate.

> ⚠️ `main` este identic cu `fixed-version`. Codul din `main` reprezintă versiunea sigură și funcțională a aplicației.


## Instalare și rulare

### Cerințe
- Node.js
- npm

### Pași

```bash
# Instaleaza dependentele
npm install

# Porneste aplicatia
npm run dev
```

Aplicația va fi disponibilă la `http://localhost:3000`.


## Tehnologii utilizate

- Node.js / Express
- SQLite
- HTML / CSS / JavaScript
