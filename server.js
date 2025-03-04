const express=require('express');
const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const cookieParser=require('cookie-parser');
require('dotenv').config();

const JWT_SECRET=process.env.JWT_SECRET;
const PORT=process.env.PORT||5000;
const DB=process.env.DB_URL

const app=express();
app.use(express.json());
app.use(cookieParser());

mongoose.connect(DB)
        .then(()=>console.log("Database connected successfully."))
        .catch(er=>console.log(er));

const userSchema=new mongoose.Schema({
    email:{type:String, required:true, unique:true},
    password:{type:String, required:true },
})        

const userModel=mongoose.model("User", userSchema);
        
const refreshTokens=[];

app.get('/', (req,res)=>{
    res.send(<>Welcome to backend</>)
})

app.post('/login-register', async(req,res)=>{
    try{
        const {email, password}= req.body;
        const user=await userModel.findOne({email});
        if(!user){
            // create new user
            const hashedPassword= await bcrypt.hash(password, 10)
            const newUser=await userModel.create({email, password:hashedPassword})
        }else{
            const isMatch=bcrypt.compare(password, user.password);
            if(!isMatch){
                return res.status(403).send({message:"Invalid credentials"})
            }
        }

        //create tokens
        const accessToken=jwt.sign({id:user._id,email,password}, JWT_SECRET, {expiresIn:"15m"});
        const refreshToken=jwt.sign({id:user._id,email,password}, JWT_SECRET, {expiresIn:"7h"});

        res.cookie('accessToken', accessToken, {httpOnly:true, secure:true, sameSite:true});
        res.cookie('refreshToken', refreshToken, {httpOnly:true, secure:true, sameSite:true});

        refreshTokens.push(refreshToken);

        res.status(200).send({message:"Authenticated successfully"});

    }catch(er){
        return res.status(500).send({message:"Internal server error", error:er.message});
    }

})

app.get('/refresh-token',(req,res)=>{
    const token=req.cookies.refreshToken || req.headers.authentication?.split(" ")[1];
    if(!token || refreshTokens.includes(token)){
        return res.status(403).send({message:"Unauthorized"});
    }

    jwt.verify(token, JWT_SECRET, (err, user)=>{
        if(err){
            return res.status(403).send({message:"Invalid token."})
        }
        const newAccessToken=jwt.sign({id:user._id, email:user.email}, JWT_SECRET, {expiresIn:"7h"});
        res.cookie('newAccessToken', newAccessToken, {httpOnly:true, secure:true, sameSite:true});
        
        res.status(200).send({message:"New access token created"});
    })
})

const middleWare=(req,res,next)=>{
    const token=req.cookie.accessToken || req.headers.authorization?.split(" ")[1];
    if(!token){
        return res.status(403).send({message:"unauthorized"});
    }

    jwt.verify(token, JWT_SECRET, (err, user)=>{
        if(err){
            return res.status(403).send("Invalid Token")
        }
        req.user=user;
        next();

    })
}


app.get('/profile',middleWare, async(req,res)=>{
    try{
        const user=await userModel.findById(req.user._id);
        res.status(200).send({user:user});
    }catch(er){
        return res.status(500).send({message:"Internal server error"})
    }
})


app.listen(PORT,()=>{
    console.log(`App is running on http://localhost:${PORT}`);
})