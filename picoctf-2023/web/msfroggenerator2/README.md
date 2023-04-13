# msfroggenerator2
Points: 500

Our teams thought process:
1. looking for xss in the javascript
2. timing attack against flag comparison
3. trying http smuggling
4. looking for exploits in the js again
5. looking for url parsing vulnerabilities (found one in traefik)
6. attempting to break CORS and all of web security
7. back to timing attacks
8. found random bug submission to the chromium monorail bug report website about self xss (it worked and we got the flag)