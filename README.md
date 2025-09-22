# JWKS-server1 project summary
Make sure to haveflask install, use this in the terminal:
pip install flask pyjwt cryptography <br />
<br />
This project has been made with the help of AI. I used ChatGPT to create the server and then debug issues with the results. I also used to make the test suite and coverage. For the creation of the server, I used this as the prompt: <br />
Develop a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter. Using python and one file. Requirements  to get full marks: 
Key Generation
Implement RSA key pair generation.
Associate a Key ID (kid) and expiry timestamp with each key.
Web server with two handlers
Serve HTTP on port 8080
A RESTful JWKS endpoint that serves the public keys in JWKS format.
Only serve keys that have not expired.
A /auth endpoint that returns an unexpired, signed JWT on a POST request.
If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry. <br />
<br />
After creating I ask to explain parts where I did not understand well. I later on finish debugging since by using the result from the prompt, it gave 31 points in the gradebot, it failed on finding a valid JWKS, and it did not found a expired JWK in JWKS. After debugging, I asked again to create a test suite code using this prompt:
I need a test suite for this code: main.py. It provided a file, but when I ran it, it failed to run on the terminal. I fixed it by using this command : <br />
python -m pytest --cov=main --cov-report=term-missing <br />
After that it worked fine and was able to complete the project.
