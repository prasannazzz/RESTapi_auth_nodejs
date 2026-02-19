const express = require("express");
const Datastore = require("nedb-promises"); //in memory database for Node.js
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken')

const config = require('./config')

const app = express();

app.use(express.json());

const users = Datastore.create("Users.db");

app.get("/", (req, res) => {
  res.send("REST API with Authentication");
});

app.post("/api/auth/register", async (request, response) => {
  try {
    const { name, email, password } = request.body;
    if (!name || !email || !password) {
      return response.status(422).json({
        //Missing required fields
        message: "Please Fill all details",
      });
    }
    if (await users.findOne({ email })) {
      return response.status(409).json({
        message: " email already exist",
      });
    }
    const hashedpassword = await bcrypt.hash(password, 10); // salt is 10
    const newUser = await users.insert({
      name,
      email,
      password: hashedpassword,
    });
    return response.status(201).json({
      message: "User registered successfully",
      id: newUser._id,
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message,
    });
  }
});
app.post("/api/auth/login", async (request, response) => {
  try {
    const { email, password } = request.body;
    if (!email || !password) {
      return response.status(422).json({
        //Missing required fields
        message: "Please Fill all details",
      })}
      const user = await users.findOne({email})
      if(!user){
        return res.status(401).json({
            message: 'Email or Password is Invalid'
        })
      }
      const passwordMatch= await bcrypt.compare(password, user.password)
      if(!passwordMatch){
         return res.status(401).json({
            message: 'Email or Password is Invalid'
        })
      }
  const accessToken = jwt.sign(
    {userId: user._id},
    config.accessTokenSecret,
    {subject: 'accessApi', expiresIn: '1h'}
) 
  return response.status(200).json({
    id: user._id,
    name: user.name,
    email: user.email,
    accessToken
  })


  

  } catch (error) {
    return response.status(500).json({
      message: error.message,
    });
  }
});

app.listen(3003, () => console.log("Server is running on port 3003"));
