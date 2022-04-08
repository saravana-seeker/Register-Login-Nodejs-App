const express = require('express')
const app = express()
const path = require('path')
const User = require('./models/User')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const dotenv = require('dotenv');
dotenv.config();
//const bodyParser = require('body-parser')

// mongoose database connection 
const mongUrl=process.env.Db_Url
const mongoose = require('mongoose')

mongoose.connect(mongUrl,(err)=>{
    if(err) {console.log(err)}
    console.log("db connected..!")
})

// //create a static file
app.use('/',express.static(path.join(__dirname,'public')))


//set template engine ejs
// embedded javascript 
app.set('view engine','ejs')



//getting a json request parsing 
app.use(express.json())


// for cookie parser
 app.use(cookieParser())

//for home page render
app.get('/',(req,res)=>{
    res.render('index')
})


// for register page render
app.get('/register',(req,res)=>{
    res.render('register')
})

//for login page render
app.get('/login',(req,res)=>{
    res.render('login')
})



//for register 
app.post('/api/register',async (req,res,next)=>{
    const {body} = req
    const username = body.username
    const password = body.password
    const name = body.name
    // validation
    if (!username || typeof username != 'string' ){
        //return res.json({status:'error',error:'invalid username'})
        res.send(403)
    }
    if (username.length < 5){
        return res.status(204).send("Invalid username")
    }



    if (!password || typeof password !='string'){
        //return res.json({status:'error',error:'invalid Password'})
        res.send(403)
    }

    if (password.length < 5){
        return res.status(203).send("Password Must be greater than 5 character")
    }


    //check the user exist or not
    const UserExist = await User.findOne({username:body.username})
    if(UserExist){
        console.log('User exist')
         return res.status(409).send("user exist")
        //return res.json({status:'error',error:'User exist'})
    }
    
    //hash the password
    const hashPasswd = await bcrypt.hash(body.password,5)
    console.log(hashPasswd)    

    //creating a user
    const user = new User({
        name:body.name,
        username:body.username,
        password:hashPasswd

    });
    try {
        const SavedUser = await user.save();
        console.log(SavedUser)
        res.status(201).send("successfully created")
    } catch (error) {
        console.log(error)
    }
    
})



// for authorization 
const authorization = (req,res,next) =>{
    const token = req.cookies.access_token
    console.log(token)
    if(!token){return res.status(403).send("Unauthorized request")}
    try {
        const data = jwt.verify(token,process.env.Jwt_Key)
        return next()
    } catch (error) {
        console.log(error)
    }
}

// for login
app.post('/api/login',async (req,res)=>{
    const {body} = req
    const username = body.username
    const password = body.password
    
    //Check the user name
    const user = await User.findOne({username:body.username})
    if (!user) {
        return res.status(403).render('login', {message:"Invalid Credentials"})
    }
    
    const ValidPassword =await  bcrypt.compare(body.password,user.password)
    if(!ValidPassword) {
        return res.status(403).render('login',{message:"Invalid Credentials"})
    }


    // create a jwt token
    const token = await jwt.sign({_id:user._id,username:user.username},process.env.Jwt_Key)
    

    //console.log(token)
    console.log('success')

    // send a token to client 
    res.cookie("access_token",token,{httpOnly: true,
        secure: process.env.NODE_ENV === "production",}).status(200).json("success")
    


    

})


// Protected content view 
//dashboard 

app.get('/dashboard',authorization,async(req,res) => {
    //getting a token form the cookie
    value = req.headers.cookie
    token = value.slice(13) 
    console.log(value)
    const data = jwt.verify(token,process.env.Jwt_Key)
    // User
    const user = await User.findOne({username:data.username})
    //console.log(user.name)
    res.render('dashboard',{name:user.name,email:data.username})


})



// for password update
app.get('/changepasswd',authorization,(req,res)=>{
    res.render('changepasswd')
})



app.post('/api/changepasswd',authorization,async(req,res) =>{
    const {body} = req
    const password = body.password
    // validation 
    if (!password || typeof password !='string'){
        return res.json({status:'error',error:'invalid Password'})
    }

    if (password.length < 5){
        return res.json({status:'error',error:'Password Must be greater than 5 character'})
    }

    // hashed passwd
    const hashPasswd = await bcrypt.hash(password,10)
    //getting a token form the cookie
    value = req.headers.cookie
    token = value.slice(13) 
    const data = jwt.verify(token,process.env.Jwt_Key)
    // User
    const _id = data._id
    console.log(_id)
    const user = await User.updateOne({_id},
        {
            $set: {hashPasswd}
        })
    // User password change return a response
    res.status(200).json("Password Change success fully ")
})


// for logout function
app.get('/logout',authorization,(req,res)=>{
    //console.log(token)
    return res.clearCookie('access_token').render('index')
})


//for 404 error
app.use('',(req,res) => {
    res.render('error')
})


//app listening 
const startApp = (port)=>{
    try {
        app.listen(3000,()=>{
            console.log("server is running http://127.0.0.1:3000")
        })
    } catch (error) {
        console.log(error)
        process.exit()

    }

}
startApp(3000)
