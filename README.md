# JWKS Server

A JWKS server built in JavaScript that has AES encryption of keys, JWT handling, user registration capabilities, and logged authentication requests.


## How to get running in your enviornment!

First, clone the repo:
`git clone git@github.com:kyibell/jwks-server.git`
Then, navigate to the jwks-server directory.

With a terminal open with the directory of the code run either:
- `nodemon`
- `node server.js`

Once you see `App is Listening...` and `Database connected` You have successfully ran the JWKS Server!
If you want to run the tests/gradebot, open a separate terminal and run the commands needed!

## NOTES ABOUT JEST (Running the tests)

Since Jest has a specific command to run my test suite, you can run `npm run coverage` because I put the script in the package.json.
