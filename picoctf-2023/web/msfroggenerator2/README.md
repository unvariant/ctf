# msfroggenerator2
Points: 500

Solution:
1. looking for xss in the javascript
2. timing attack against flag comparison
3. trying http smuggling
4. attempted hop to hop
5. looking for exploits in the js again
6. looking for url parsing vulnerabilities (found one in traefik)
7. attempting to break CORS and all of web security
8. back to timing attacks
9. found random bug submission to the chromium monorail bug report website about self xss (it worked and we got the flag)

In all seriousness, our solution used a bug in traefik that allows semicolons as valid url parameter delimiters, while
the nginx and nodejs url parsing libraries only treats ampersand as the url parameter delimiter, which allows us to control
the url parameter and where the bot redirects to.