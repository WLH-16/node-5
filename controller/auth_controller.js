const bcrypt = require("bcryptjs");
module.exports = {
  register: async (req, res) => {
    // get db instance
    const db = req.app.get("db");
    // get email and password from body
    const { email, password } = req.body;
    // search for an existing email
    const foundUser = await db.get_user([email]);
    // check to see if user is found because we don't want to be able to register duplicates
    if (foundUser[0])
      return res.status(409).send("Sorry, email already exists.");
    // If user is not found, create a new hash and salt
    const salt = bcrypt.genSaltSync(15);
    const hash = bcrypt.hashSync(password, salt);
    // Add user and hash to database
    const newUser = await db.register_user([email, hash]);
    // Add user to the session
    req.session.user = newUser[0];
    // Send user back
    res.status(200).send(req.session.user);
  },
  login: async (req, res) => {
    // get db instance
    const db = req.app.get("db");
    // get email and password from body
    const { email, password } = req.body;
    // search for an existing email
    const foundUser = await db.get_user([email]);
    // check to see if user is found - the data always comes back from the database in an array and even if an array is empty it is interpreted as a truthy value. in the if statement below we're checking to see if there's anything in the user array coming back because if something does come back it means 
    if (!foundUser[0])
      return res.status(409).send("Sorry, email not found");
    //if the above if statement fails it means the user will be found so compare password to the hashed password stored in db
    
    //creates boolean value authenticated as true or false based on whether or not the password is correct
    const authenticated = bcrypt.compareSync(password, foundUser[0].password);
    // check to see if authenticated is true or false
    if (authenticated) {
      // remove user password from the object before storing on the session
      delete foundUser[0].password;
      // if authed set user to session and make a response
      req.session.user = foundUser[0];
      // send response
      res.status(200).send(req.session.user);
    } else {
      // if failure send error message
      return res.status(401).send("Inccorect username or password");
    }
  }
};
