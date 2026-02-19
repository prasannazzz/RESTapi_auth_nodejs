const express = require("express");
const Datastore = require("nedb-promises"); //in memory database for Node.js
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken')

const config = require('./config')

const app = express();

app.use(express.json());

const users = Datastore.create("Users.db");
const userRefreshTokens = Datastore.create("UserRefreshTokens.db");
const userInvalidTokens = Datastore.create("UserInvalidTokens.db");

app.get("/", (request, response) => {
  response.send("REST API with Authentication");
});

app.post("/api/auth/register", async (request, response) => {
  try {
    const { name, email, password , role} = request.body;
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
      role: role ?? 'member'
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
      });
    }
    const user = await users.findOne({ email });
    if (!user) {
      return response.status(401).json({
        message: "Email or Password is Invalid",
      });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return response.status(401).json({
        message: "Email or Password is Invalid",
      });
    }
    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: config.accessTokenExpiresIn },
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn },
    );
    await userRefreshTokens.insert({
      userId: user._id,
      refreshToken
    })
    return response.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
      refreshToken
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message,
    });
  }
});

app.post('/api/auth/refresh-token', async (request, response) => {
    try {
       const { refreshToken } =request.body
       if(!refreshToken){
        return response.status(401).json({ message: 'Refresh token not found'})
       }
       const decodedRefreshToken = jwt.verify(refreshToken,config.refreshTokenSecret)
       const userRefreshToken=await userRefreshTokens.findOne({refreshToken,userId: decodedRefreshToken.userId})
       if(!userRefreshToken){
        return response.status(401).json({message: 'Refresh token not found'})
       }
       await userRefreshTokens.remove({_id: userRefreshToken._id})
       await userRefreshTokens.compactDatafile()
    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: config.accessTokenExpiresIn },
    );

    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn },
    );
    await userRefreshTokens.insert({
         userId: decodedRefreshToken.userId,
         refreshToken: newRefreshToken
    })
    return response.status(200).json({
      accessToken,
      refreshToken: newRefreshToken
    });
       
    } catch (error) {
        if(error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError){
            return response.status(401).json({message: 'Refresh token invalid or expired'})
        }
        return response.status(500).json({message:error.message})
    }
})

app.get('/api/auth/logout', ensureAuthenticated, async (request, response) => {
    try {
        await userRefreshTokens.remove({userId: request.user.id})
        await userRefreshTokens.compactDatafile()

        await userInvalidTokens.insert({
            token: request.accessToken.value,
            userId: request.user.id,
            expirationTime: request.accessToken.exp
        })
        return response.status(204).send()
    } catch (error) {
        return response.status(500).json({message: error.message})
    }
})

app.get('/api/users/current', ensureAuthenticated,async(request, response) => {
   try {
    const user = await users.findOne({_id: request.user.id})
    return response.status(200).json({
        id:user._id,
        name: user.name,
        email: user.email 
    })
   } catch (error) {
      return response.status(500).json({
            message: error.message
        })
   }
});

app.get('/api/admin',ensureAuthenticated, authorize(['admin']),(request,response) => {
    return response.status(200).json({message: 'Only admins can access this route'})
});

app.get('/api/moderator',ensureAuthenticated, authorize(['admin', 'moderator']),(request,response) => {
  return response.status(200).json({message: 'Only admins and moderator can access this route'})
});

async function ensureAuthenticated(request,response,next){
    const accessToken = request.headers.authorization
    if(!accessToken){
        return response.status(401).json({
            message: 'Access token not found'
        })
    }
    if (await userInvalidTokens.findOne({ token: accessToken })) {
        return response.status(401).json({
                message: 'Invalid Access Token', code: 'InvalidAccessToken'
        })
    }
    try {
        const decodedAccessToken =jwt.verify(accessToken, config.accessTokenSecret)
        request.accessToken={value: accessToken, exp: decodedAccessToken.exp}
        request.user={id: decodedAccessToken.userId}
        next()
    } catch (error) {
        if(error instanceof jwt.TokenExpiredError){
           return response.status(401).json({
                message: 'Access Token Expired', code: 'AccessTokenExpired'
            })
        }else if(error instanceof jwt.JsonWebTokenError){
            return response.status(401).json({
                message: 'Invalid Access Token', code: 'InvalidAccessToken'
            })
        }else{
            return response.status(500).json({
                message: error.message
            })
        }
    }
}

function authorize(roles=[]){
    return async function (request,response, next){
        const user = await users.findOne({_id: request.user.id})
        if(!user || !roles.includes(user.role)){
            return response.status(403).json({
                message: 'Access Denied'
            })
        }
        next()
    }
}

app.listen(3003, () => console.log("Server is running on port 3003"));
